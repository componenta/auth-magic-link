<?php

declare(strict_types=1);

namespace Componenta\Auth\MagicLink\Tests;

use Componenta\Auth\MagicLink\MagicLinkExtractor;
use Componenta\Auth\MagicLink\MagicLinkPayload;
use Componenta\Auth\Token\TokenCredential;
use Componenta\Identity\Uuid;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class MagicLinkExtractorTest extends TestCase
{
    public function testExtractsOpaqueCredentialAndBrowserBindingOnlyFromPostBody(): void
    {
        $credential = TokenCredential::fromBytes(str_repeat('a', 32));
        $binding = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
        $extractor = new MagicLinkExtractor();
        $payload = $extractor->extract(
            (new ServerRequest('POST', '/verify'))
                ->withParsedBody([
                    'token' => $credential->toString(),
                    'binding' => $binding->toString(),
                ]),
        );

        self::assertInstanceOf(MagicLinkPayload::class, $payload);
        self::assertSame(
            $credential->toString(),
            $payload->credential->toString(),
        );
        self::assertTrue($payload->bindingId->equals($binding));
        self::assertNull($extractor->extract(
            (new ServerRequest('GET', '/verify'))
                ->withQueryParams([
                    'token' => $credential->toString(),
                    'binding' => $binding->toString(),
                ]),
        ));
    }
}
