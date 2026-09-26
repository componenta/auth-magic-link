<?php

declare(strict_types=1);

namespace Componenta\Auth\MagicLink;

use Componenta\Auth\Http\Exception\InvalidPayloadException;
use Componenta\Auth\Http\PayloadExtractorInterface;
use Componenta\Auth\Token\TokenCredential;
use Componenta\Identity\Uuid;
use Psr\Http\Message\ServerRequestInterface;

final readonly class MagicLinkExtractor implements PayloadExtractorInterface
{
    public function __construct(
        public string $tokenField = 'token',
        public string $bindingField = 'binding',
    ) {
        foreach ([$this->tokenField, $this->bindingField] as $field) {
            if (preg_match('/\A[A-Za-z_][A-Za-z0-9_.-]*\z/D', $field) !== 1) {
                throw new \InvalidArgumentException(
                    'Magic-link field name is invalid.',
                );
            }
        }

        if ($this->tokenField === $this->bindingField) {
            throw new \InvalidArgumentException(
                'Magic-link token and binding fields must differ.',
            );
        }
    }

    #[\Override]
    public function extract(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ?object {
        if (strtoupper($request->getMethod()) !== 'POST') {
            return null;
        }

        $body = $request->getParsedBody();

        if ($body === null) {
            return null;
        }

        if (!is_array($body)) {
            throw InvalidPayloadException::invalidField('body');
        }

        if (!array_key_exists($this->tokenField, $body)) {
            return null;
        }

        if (!array_key_exists($this->bindingField, $body)) {
            throw InvalidPayloadException::missingField($this->bindingField);
        }

        $rawToken = $body[$this->tokenField];
        $rawBinding = $body[$this->bindingField];

        if (!is_string($rawToken)) {
            throw InvalidPayloadException::invalidField($this->tokenField);
        }

        if (!is_string($rawBinding)) {
            throw InvalidPayloadException::invalidField($this->bindingField);
        }

        try {
            $credential = TokenCredential::fromString($rawToken);
        } catch (\InvalidArgumentException) {
            throw InvalidPayloadException::invalidField($this->tokenField);
        }

        try {
            $binding = Uuid::fromString($rawBinding);
        } catch (\InvalidArgumentException) {
            throw InvalidPayloadException::invalidField($this->bindingField);
        }

        return new MagicLinkPayload($credential, $binding);
    }
}
