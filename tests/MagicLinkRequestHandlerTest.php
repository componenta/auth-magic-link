<?php

declare(strict_types=1);

namespace Componenta\Auth\MagicLink\Tests;

use Componenta\Auth\MagicLink\MagicLinkRequestHandler;
use Componenta\Auth\Session\Http\PreAuthenticationCookieTransport;
use Componenta\Auth\Session\Http\PreAuthenticationGrantPublisher;
use Componenta\Auth\Session\PreAuthenticationCredential;
use Componenta\Auth\Session\PreAuthenticationGrant;
use Componenta\Auth\Session\PreAuthenticationManagerInterface;
use Componenta\Auth\Session\PreAuthenticationRequestToken;
use Componenta\Auth\Session\PreAuthenticationTransaction;
use Componenta\Auth\Token\TokenRequest;
use Componenta\Auth\Token\TokenRequestQueueInterface;
use Componenta\Identity\Uuid;
use DateTimeImmutable;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Nyholm\Psr7\Stream;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

final class MagicLinkRequestHandlerTest extends TestCase
{
    /** @return iterable<string, array{string}> */
    public static function responseStreams(): iterable
    {
        foreach (['complete', 'partial', 'stalled', 'throwing'] as $mode) {
            yield $mode => [$mode];
        }
    }

    #[DataProvider('responseStreams')]
    public function testCompleteBodyIsPreparedBeforeCreatingOrQueuingAGrant(string $mode): void
    {
        $manager = new MagicLinkPreAuthManagerFixture(self::grant());
        $queue = new MagicLinkQueueFixture();
        $sink = new class {
            public string $body = '';
            public int $calls = 0;
        };
        $failure = new \RuntimeException('Synthetic stream failure.');
        $stream = $this->createStub(StreamInterface::class);
        $stream->method('write')->willReturnCallback(static function (string $bytes) use ($sink, $mode, $failure): int {
            if (++$sink->calls > 1) {
                if ($mode === 'stalled') {
                    return 0;
                }
                if ($mode === 'throwing') {
                    throw $failure;
                }
            }

            $written = $mode === 'complete' ? strlen($bytes) : min(7, strlen($bytes));
            $sink->body .= substr($bytes, 0, $written);

            return $written;
        });
        $stream->method('__toString')->willReturnCallback(static fn(): string => $sink->body);
        $responses = $this->createStub(ResponseFactoryInterface::class);
        $responses->method('createResponse')->willReturn(new Response(200, [], $stream));
        $handler = new MagicLinkRequestHandler($queue, $manager,
            new PreAuthenticationGrantPublisher(new PreAuthenticationCookieTransport()), $responses);
        $failureObserved = null;
        $response = null;

        try {
            $response = $handler->handle((new ServerRequest('POST', '/magic-link'))
                ->withParsedBody(['identity' => 'user@example.test']));
        } catch (\RuntimeException $exception) {
            $failureObserved = $exception;
        }

        if (in_array($mode, ['stalled', 'throwing'], true)) {
            self::assertInstanceOf(\RuntimeException::class, $failureObserved, 'Incomplete response must not be returned as success.');
            self::assertNull($response);
            self::assertNull($manager->createdTtl);
            self::assertNull($queue->request);
            if ($mode === 'throwing') {
                self::assertSame($failure, $failureObserved);
            }

            return;
        }

        self::assertNull($failureObserved);
        self::assertInstanceOf(ResponseInterface::class, $response);
        self::assertSame(200, $response->getStatusCode());
        self::assertJson((string) $response->getBody());
        self::assertArrayHasKey('message', json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR));
        self::assertSame(600, $manager->createdTtl);
        self::assertInstanceOf(TokenRequest::class, $queue->request);
    }

    /** @return iterable<string, array{string}> */
    public static function failedPublicationHeaders(): iterable
    {
        yield 'cookie' => ['Set-Cookie'];
        yield 'request token' => ['X-Pre-Auth-Token'];
        yield 'cache policy' => ['Pragma'];
    }

    #[DataProvider('failedPublicationHeaders')]
    public function testPublicationFailureConsumesCreatedPreAuthGrant(string $failedHeader): void
    {
        $grant = self::grant();
        $manager = new MagicLinkPreAuthManagerFixture($grant);
        $queue = new MagicLinkQueueFixture();
        $failure = new \RuntimeException('response publication failed');
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getBody')->willReturn(Stream::create(''));
        $response->method('getHeader')->willReturn([]);
        $response->method('withoutHeader')->willReturnSelf();
        $writeHeader = static function (string $name, mixed $value) use (
            $manager,
            $failedHeader,
            $failure,
            $response,
        ): ResponseInterface {
            if ($manager->createdTtl !== null && $name === $failedHeader) {
                throw $failure;
            }

            return $response;
        };
        $response->method('withHeader')->willReturnCallback($writeHeader);
        $response->method('withAddedHeader')->willReturnCallback($writeHeader);
        $responses = $this->createStub(ResponseFactoryInterface::class);
        $responses->method('createResponse')->willReturn($response);

        try {
            (new MagicLinkRequestHandler(
                $queue,
                $manager,
                new PreAuthenticationGrantPublisher(new PreAuthenticationCookieTransport()),
                $responses,
            ))->handle((new ServerRequest('POST', '/magic-link'))
                ->withParsedBody(['identity' => 'user@example.test']));
            self::fail('The response failure must be propagated.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        self::assertSame(1, $manager->consumptions);
        self::assertNull($queue->request);
    }

    public function testRequestCreatesBrowserBindingAndQueuesSameTransaction(): void
    {
        $grant = self::grant();
        $manager = new MagicLinkPreAuthManagerFixture($grant);
        $queue = new MagicLinkQueueFixture();
        $responses = $this->createStub(ResponseFactoryInterface::class);
        $responses->method('createResponse')->willReturnCallback(
            static fn(int $status): Response => new Response($status),
        );
        $request = (new ServerRequest('POST', '/magic-link'))
            ->withParsedBody(['identity' => 'user@example.com']);

        $response = (new MagicLinkRequestHandler(
            $queue,
            $manager,
            new PreAuthenticationGrantPublisher(
                new PreAuthenticationCookieTransport(),
            ),
            $responses,
        ))->handle($request);

        self::assertSame(600, $manager->createdTtl);
        self::assertSame(0, $manager->consumptions);
        self::assertInstanceOf(TokenRequest::class, $queue->request);
        self::assertSame('user@example.com', $queue->request->identity);
        self::assertSame('magic_link', $queue->request->purpose->value);
        self::assertSame(
            $grant->transaction->uuid->toString(),
            $queue->request->context['binding'] ?? null,
        );
        self::assertStringContainsString(
            '__Host-auth_pre=',
            $response->getHeaderLine('Set-Cookie'),
        );
        self::assertSame(
            $grant->requestToken->toString(),
            $response->getHeaderLine('X-Pre-Auth-Token'),
        );
    }

    public function testQueueFailureConsumesCreatedPreAuthGrant(): void
    {
        $grant = self::grant();
        $manager = new MagicLinkPreAuthManagerFixture($grant);
        $queue = new MagicLinkQueueFixture(
            new \RuntimeException('queue failed'),
        );
        $responses = $this->createStub(ResponseFactoryInterface::class);
        $responses->method('createResponse')->willReturnCallback(
            static fn(int $status): Response => new Response($status),
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('queue failed');

        try {
            (new MagicLinkRequestHandler(
                $queue,
                $manager,
                new PreAuthenticationGrantPublisher(
                    new PreAuthenticationCookieTransport(),
                ),
                $responses,
            ))->handle(
                (new ServerRequest('POST', '/magic-link'))
                    ->withParsedBody([
                        'identity' => 'user@example.com',
                    ]),
            );
        } finally {
            self::assertSame(1, $manager->consumptions);
        }
    }

    private static function grant(): PreAuthenticationGrant
    {
        $created = new DateTimeImmutable('2030-01-01T00:00:00+00:00');

        return new PreAuthenticationGrant(
            new PreAuthenticationTransaction(
                Uuid::fromString(
                    '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
                ),
                $created,
                $created->modify('+10 minutes'),
            ),
            PreAuthenticationCredential::fromBytes(str_repeat('a', 32)),
            PreAuthenticationRequestToken::fromBytes(str_repeat('b', 32)),
        );
    }
}

final class MagicLinkPreAuthManagerFixture implements
    PreAuthenticationManagerInterface
{
    public ?int $createdTtl = null;
    public int $consumptions = 0;

    public function __construct(private PreAuthenticationGrant $grant) {}

    public function create(int $ttlSeconds = 300): PreAuthenticationGrant
    {
        $this->createdTtl = $ttlSeconds;

        return $this->grant;
    }

    public function verify(
        PreAuthenticationCredential $credential,
        PreAuthenticationRequestToken $requestToken,
    ): ?PreAuthenticationTransaction {
        return $this->grant->transaction;
    }

    public function consume(
        PreAuthenticationCredential $credential,
        PreAuthenticationRequestToken $requestToken,
    ): ?PreAuthenticationTransaction {
        ++$this->consumptions;

        return $this->grant->transaction;
    }
}

final class MagicLinkQueueFixture implements TokenRequestQueueInterface
{
    public ?TokenRequest $request = null;

    public function __construct(
        private ?\Throwable $failure = null,
    ) {}

    public function enqueue(TokenRequest $request): void
    {
        $this->request = $request;

        if ($this->failure !== null) {
            throw $this->failure;
        }
    }
}
