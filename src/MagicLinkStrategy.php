<?php

declare(strict_types=1);

namespace Componenta\Auth\MagicLink;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\IdentityProviderInterface;
use Componenta\Auth\MagicLink\Denied\InvalidMagicLink;
use Componenta\Auth\Session\PreAuthenticationTransaction;
use Componenta\Auth\Token\TokenManagerInterface;
use Componenta\Auth\Token\TokenPurpose;

final readonly class MagicLinkStrategy implements AuthenticationStrategyInterface
{
    private TokenPurpose $purpose;

    public function __construct(
        private TokenManagerInterface $tokens,
        private IdentityProviderInterface $identities,
    ) {
        $this->purpose = new TokenPurpose('magic_link');
    }

    #[\Override]
    public function supports(
        #[\SensitiveParameter]
        object $payload,
        #[\SensitiveParameter]
        ContextInterface $context,
    ): bool {
        return $payload instanceof MagicLinkPayload;
    }

    #[\Override]
    public function attempt(
        #[\SensitiveParameter]
        object $payload,
        #[\SensitiveParameter]
        ContextInterface $context,
    ): AuthenticationResult {
        if (!$payload instanceof MagicLinkPayload) {
            return $this->denied();
        }

        $preAuthentication = $context->getAttribute(
            PreAuthenticationTransaction::class,
        );

        if (
            !$preAuthentication instanceof PreAuthenticationTransaction
            || !$payload->bindingId->equals($preAuthentication->uuid)
        ) {
            return $this->denied();
        }

        $record = $this->tokens->consume(
            $payload->credential,
            $this->purpose,
        );

        if ($record === null) {
            return $this->denied();
        }

        $identity = $this->identities->findByUuid($record->subjectId);

        if (
            $identity === null
            || !$identity->uuid->equals($record->subjectId)
        ) {
            return $this->denied();
        }

        return new AuthenticationResult(
            subject: $identity,
            evidence: new AuthenticationEvidence(
                methods: ['magic_link'],
                capabilities: ['possession'],
            ),
        );
    }

    private function denied(): AuthenticationResult
    {
        return new AuthenticationResult(new InvalidMagicLink());
    }
}
