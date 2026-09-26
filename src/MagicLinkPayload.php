<?php

declare(strict_types=1);

namespace Componenta\Auth\MagicLink;

use Componenta\Auth\Token\TokenCredential;

final readonly class MagicLinkPayload implements \JsonSerializable
{
    public function __construct(
        #[\SensitiveParameter]
        public TokenCredential $credential,
    ) {}

    /** @return array{credential: string} */
    public function __debugInfo(): array
    {
        return ['credential' => '[REDACTED]'];
    }

    /** @return array{credential: string} */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
