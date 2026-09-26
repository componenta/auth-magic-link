<?php

declare(strict_types=1);

namespace Componenta\Auth\MagicLink\Denied;

use Componenta\Auth\DeniedReasonInterface;

final class InvalidMagicLink implements DeniedReasonInterface
{
    public string $code {
        get => 'invalid_token';
    }

    /** @var array<string, mixed> */
    public array $attributes {
        get => [];
    }
}
