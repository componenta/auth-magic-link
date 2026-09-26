<?php

declare(strict_types=1);

namespace Componenta\Auth\MagicLink\Tests;

use Componenta\Auth\Context;
use Componenta\Auth\IdentityProviderInterface;
use Componenta\Auth\MagicLink\Denied\InvalidMagicLink;
use Componenta\Auth\MagicLink\MagicLinkPayload;
use Componenta\Auth\MagicLink\MagicLinkStrategy;
use Componenta\Auth\Session\PreAuthenticationTransaction;
use Componenta\Auth\Token\TokenCredential;
use Componenta\Auth\Token\TokenManagerInterface;
use Componenta\Auth\Token\TokenPurpose;
use Componenta\Auth\Token\TokenRecord;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class MagicLinkStrategyTest extends TestCase
{
    public function testConsumesTokenOnlyWhenBindingMatchesCurrentPreAuth(): void
    {
        $identity = new MagicLinkIdentityFixture();
        $credential = TokenCredential::fromBytes(str_repeat('a', 32));
        $binding = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abd',
        );
        $record = new TokenRecord(
            $identity->uuid,
            new TokenPurpose('magic_link'),
            new DateTimeImmutable('2030-01-01T00:00:00+00:00'),
            new DateTimeImmutable('2030-01-01T00:05:00+00:00'),
            new DateTimeImmutable('2030-01-01T00:01:00+00:00'),
            binding: $binding->toString(),
        );
        $tokens = $this->createMock(TokenManagerInterface::class);
        $tokens->expects(self::once())
            ->method('consume')
            ->with(
                self::callback(
                    static fn(TokenCredential $value): bool =>
                        $value->toString() === $credential->toString(),
                ),
                self::callback(
                    static fn(TokenPurpose $purpose): bool =>
                        $purpose->value === 'magic_link',
                ),
                $binding->toString(),
            )
            ->willReturn($record);
        $identities = $this->createStub(IdentityProviderInterface::class);
        $identities->method('findByUuid')->willReturn($identity);
        $preAuth = new PreAuthenticationTransaction(
            $binding,
            new DateTimeImmutable('2030-01-01T00:00:00+00:00'),
            new DateTimeImmutable('2030-01-01T00:05:00+00:00'),
        );

        $result = (new MagicLinkStrategy($tokens, $identities))->attempt(
            new MagicLinkPayload($credential, $binding),
            new Context([
                PreAuthenticationTransaction::class => $preAuth,
            ]),
        );

        self::assertSame($identity, $result->subject);
        self::assertSame(['magic_link'], $result->evidence?->methods);
        self::assertSame(
            ['one_time_link'],
            $result->evidence?->capabilities,
        );
    }

    public function testMismatchedBindingDoesNotConsumeToken(): void
    {
        $tokens = $this->createMock(TokenManagerInterface::class);
        $tokens->expects(self::never())->method('consume');
        $identities = $this->createMock(IdentityProviderInterface::class);
        $identities->expects(self::never())->method('findByUuid');
        $payloadBinding = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abd',
        );
        $currentBinding = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abe',
        );
        $preAuth = new PreAuthenticationTransaction(
            $currentBinding,
            new DateTimeImmutable('2030-01-01T00:00:00+00:00'),
            new DateTimeImmutable('2030-01-01T00:05:00+00:00'),
        );

        $result = (new MagicLinkStrategy($tokens, $identities))->attempt(
            new MagicLinkPayload(
                TokenCredential::fromBytes(str_repeat('a', 32)),
                $payloadBinding,
            ),
            new Context([
                PreAuthenticationTransaction::class => $preAuth,
            ]),
        );

        self::assertInstanceOf(InvalidMagicLink::class, $result->subject);
    }
}

final class MagicLinkIdentityFixture implements IdentityInterface
{
    public UuidInterface $uuid {
        get => Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
    }
}
