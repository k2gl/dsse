<?php

declare(strict_types=1);

namespace K2gl\Dsse\Tests;

use K2gl\Dsse\Pae;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(Pae::class)]
final class PaeTest extends TestCase
{
    public function testEncodesTheOfficialSpecVector(): void
    {
        fact(Pae::encode('http://example.com/HelloWorld', 'hello world'))
            ->is('DSSEv1 29 http://example.com/HelloWorld 11 hello world');
    }

    public function testUsesByteLengthNotCharacterLength(): void
    {
        // "héllo" is 5 characters but 6 bytes (é is two bytes in UTF-8).
        fact(Pae::encode('héllo', ''))->is('DSSEv1 6 héllo 0 ');
    }

    public function testIsBinarySafe(): void
    {
        $body = "a\x00b";
        fact(Pae::encode('t', $body))->is("DSSEv1 1 t 3 a\x00b");
    }
}
