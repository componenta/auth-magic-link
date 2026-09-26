<?php

declare(strict_types=1);

namespace Componenta\Auth\MagicLink;

use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Context;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\MagicLink\Denied\InvalidMagicLink;
use Componenta\Auth\Session\AuthenticatedSessionIssuer;
use Componenta\Auth\Session\Http\AuthSessionGrantPublisher;
use Componenta\Auth\Session\Http\PreAuthenticationConsumer;
use Componenta\Auth\Session\Http\PreAuthenticationGrantPublisher;
use Componenta\Auth\Session\Http\SessionMetadataExtractorInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class MagicLinkVerifyHandler implements RequestHandlerInterface
{
    public function __construct(
        private MagicLinkExtractor $extractor,
        private AuthenticatorInterface $authenticator,
        private PreAuthenticationConsumer $preAuthentication,
        private PreAuthenticationGrantPublisher $preAuthenticationPublisher,
        private AuthenticatedSessionIssuer $sessionIssuer,
        private AuthSessionGrantPublisher $sessionPublisher,
        private SessionMetadataExtractorInterface $metadata,
        private DeniedResponseFactoryInterface $deniedResponses,
        private ResponseFactoryInterface $responses,
    ) {}

    #[\Override]
    public function handle(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ResponseInterface {
        if (strtoupper($request->getMethod()) !== 'POST') {
            return $this->responses->createResponse(405)
                ->withHeader('Allow', 'POST')
                ->withHeader('Cache-Control', 'no-store')
                ->withHeader('Pragma', 'no-cache');
        }

        $payload = $this->extractor->extract($request);

        if (!$payload instanceof MagicLinkPayload) {
            return $this->denied(new InvalidMagicLink());
        }

        if ($this->preAuthentication->verify($request) === null) {
            return $this->denied(new InvalidMagicLink());
        }

        // Build the success response before the one-time magic-link bearer is
        // consumed by the strategy.
        $response = $this->preAuthenticationPublisher->clear(
            $this->responses->createResponse(204),
        );

        $result = $this->authenticator->attempt($payload, new Context([
            ServerRequestInterface::class => $request,
            ContextInterface::EXTRACTOR => $this->extractor,
        ]));

        if ($result->subject instanceof DeniedReasonInterface) {
            return $this->preAuthenticationPublisher->clear(
                $this->deniedResponses->create($result->subject),
            );
        }

        $evidence = $result->evidence
            ?? throw new \LogicException(
                'Successful magic-link authentication must contain evidence.',
            );

        if ($this->preAuthentication->consume($request) === null) {
            return $this->preAuthenticationPublisher->clear(
                $this->denied(new InvalidMagicLink()),
            );
        }

        $grant = $this->sessionIssuer->issue(
            $result->subject,
            $evidence,
            $this->metadata->extract($request),
        );

        return $this->sessionPublisher->publish(
            $request,
            $response,
            $grant,
        );
    }

    private function denied(InvalidMagicLink $reason): ResponseInterface
    {
        return $this->deniedResponses->create($reason);
    }
}
