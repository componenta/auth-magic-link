<?php

declare(strict_types=1);

namespace Componenta\Auth\MagicLink;

use Componenta\Auth\Token\TokenCredential;
use Componenta\Identity\UuidInterface;

final readonly class MagicLinkPayload implements \JsonSerializable
{
    public function __construct(
        #[\SensitiveParameter]
        public TokenCredential $credential,
        public UuidInterface $bindingId,
    ) {}

    /** @return array{credential: string, bindingId: string} */
    public function __debugInfo(): array
    {
        return [
            'credential' => '[REDACTED]',
            'bindingId' => $this->bindingId->toString(),
        ];
    }

    /** @return array{credential: string, bindingId: string} */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
