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
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;

final class MagicLinkRequestHandlerTest extends TestCase
{
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
