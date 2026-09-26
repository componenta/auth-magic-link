<?php

declare(strict_types=1);

namespace Componenta\Auth\MagicLink\Tests;

use Componenta\Auth\MagicLink\MagicLinkExtractor;
use Componenta\Auth\MagicLink\MagicLinkPayload;
use Componenta\Auth\Token\TokenCredential;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class MagicLinkExtractorTest extends TestCase
{
    public function testExtractsOpaqueCredentialOnlyFromPostBody(): void
    {
        $credential = TokenCredential::fromBytes(str_repeat('a', 32));
        $extractor = new MagicLinkExtractor();
        $payload = $extractor->extract(
            (new ServerRequest('POST', '/verify'))
                ->withParsedBody(['token' => $credential->toString()]),
        );

        self::assertInstanceOf(MagicLinkPayload::class, $payload);
        self::assertSame(
            $credential->toString(),
            $payload->credential->toString(),
        );
        self::assertNull($extractor->extract(
            (new ServerRequest('GET', '/verify'))
                ->withQueryParams(['token' => $credential->toString()]),
        ));
    }
}
