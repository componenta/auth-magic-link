<?php

declare(strict_types=1);

namespace Componenta\Auth\MagicLink;

use Componenta\Auth\Http\Exception\InvalidPayloadException;
use Componenta\Auth\Http\PayloadExtractorInterface;
use Componenta\Auth\Token\TokenCredential;
use Psr\Http\Message\ServerRequestInterface;

final readonly class MagicLinkExtractor implements PayloadExtractorInterface
{
    public function __construct(public string $field = 'token')
    {
        if (preg_match('/\A[A-Za-z_][A-Za-z0-9_.-]*\z/D', $this->field) !== 1) {
            throw new \InvalidArgumentException(
                'Magic-link token field is invalid.',
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

        if (!array_key_exists($this->field, $body)) {
            return null;
        }

        $raw = $body[$this->field];

        if (!is_string($raw)) {
            throw InvalidPayloadException::invalidField($this->field);
        }

        try {
            return new MagicLinkPayload(TokenCredential::fromString($raw));
        } catch (\InvalidArgumentException) {
            throw InvalidPayloadException::invalidField($this->field);
        }
    }
}
