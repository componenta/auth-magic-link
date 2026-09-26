<?php

declare(strict_types=1);

namespace Componenta\Auth\MagicLink;

use Componenta\Auth\Session\Http\PreAuthenticationGrantPublisher;
use Componenta\Auth\Session\PreAuthenticationManagerInterface;
use Componenta\Auth\Token\TokenPurpose;
use Componenta\Auth\Token\TokenRequest;
use Componenta\Auth\Token\TokenRequestQueueInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class MagicLinkRequestHandler implements RequestHandlerInterface
{
    public function __construct(
        private TokenRequestQueueInterface $queue,
        private PreAuthenticationManagerInterface $preAuthentication,
        private PreAuthenticationGrantPublisher $publisher,
        private ResponseFactoryInterface $responses,
        private string $identityField = 'identity',
        private int $preAuthenticationTtlSeconds = 600,
    ) {
        if (
            preg_match(
                '/\A[A-Za-z_][A-Za-z0-9_.-]*\z/D',
                $this->identityField,
            ) !== 1
        ) {
            throw new \InvalidArgumentException(
                'Magic-link identity field is invalid.',
            );
        }

        if (
            $this->preAuthenticationTtlSeconds < 30
            || $this->preAuthenticationTtlSeconds > 1800
        ) {
            throw new \InvalidArgumentException(
                'Magic-link pre-authentication TTL is invalid.',
            );
        }
    }

    #[\Override]
    public function handle(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ResponseInterface {
        $body = $request->getParsedBody();
        $identity = is_array($body)
            ? ($body[$this->identityField] ?? null)
            : null;

        if (
            !is_string($identity)
            || $identity === ''
            || strlen($identity) > 320
            || trim($identity) !== $identity
            || preg_match('/[\x00-\x1F\x7F]/', $identity) === 1
        ) {
            return $this->json(400, ['error' => 'invalid_identity']);
        }

        $response = $this->json(200, [
            'message' => 'If the account exists, a link has been sent.',
        ]);
        $grant = $this->preAuthentication->create(
            $this->preAuthenticationTtlSeconds,
        );
        $response = $this->publisher->publish($response, $grant);
        $work = new TokenRequest(
            identity: $identity,
            purpose: new TokenPurpose('magic_link'),
            context: [
                'binding' => $grant->transaction->uuid->toString(),
            ],
        );

        try {
            $this->queue->enqueue($work);
        } catch (\Throwable $exception) {
            $this->preAuthentication->consume(
                $grant->credential,
                $grant->requestToken,
            );

            throw $exception;
        }

        return $response;
    }

    /** @param array<string, mixed> $payload */
    private function json(int $status, array $payload): ResponseInterface
    {
        $response = $this->responses->createResponse($status);
        $response->getBody()->write(
            json_encode($payload, JSON_THROW_ON_ERROR),
        );

        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');
    }
}
