<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ExecutionChallengeGenerator;
use PHPUnit\Framework\TestCase;

/**
 * Differential decode/verify corpus of the ExecutionChallengeV1
 * dimension: the adversarial program and trace shapes of the audit (op
 * count too large, sibling index forged, observe out of bounds,
 * trailing bytes, bad op version, overlong operand, duplicate entry,
 * missing entry, appended garbage). One valid executed trace per
 * execution version completes the corpus, each case with its expected
 * classification. Every case
 * embeds a pinned program blob (the fixed key and nonce of the
 * cross-language vectors) and a concrete trace literal, so the
 * verdicts are structural. The companion Rust test in
 * tests/execution_mutation_fuzz.rs consumes the same embedded corpus
 * and must land on the same classification for every case.
 */
final class ExecutionDifferentialCorpusTest extends TestCase
{
    private const NONCE = 'xAfSYcl6VyvtYZcQUhvXxin2pojnG5TmZoHg7K6NG3s=';

    /**
     * The corpus: name, execution version, program blob, trace and the
     * expected decode/verify verdict. Classifications: malformed (the
     * program is outside the protocol language), execution_mismatch
     * (the program parses but the trace is not a valid execution of
     * it) and valid.
     *
     * @var list<array{name: string, version: int, program: string, trace: string, expected: string}>
     */
    private const CORPUS = [
        [
            'name' => 'v1-valid',
            'version' => 1,
            'program' => 'AQVsb2dpbgxsb2dpbi1hY3Rpb24BFhA4D3JWcHNlVHl2TVR4TG1zKxcJVXJYczFGMllaEh8PclZwc2VUeXZNVHhMbXMrHA9yVnBzZVR5dk1UeExtcysdD3JWcHNlVHl2TVR4TG1zKyAXCzJBcUxDOXNKQjR2BZbLHEPX1bDYB/KirhATuo0oGxILsBkQUA8xV2JFc3cvWGFsSkdSUlAJt5MaEOAQZFNIazI0RkFsM1diODVDMxQkFgVySmkjWQdwo5mMcPosjwLkcZPOX9oyWQ==',
            'trace' => 'dcreate(clZwc2VUeXZNVHhMbXMr);cadd(VXJYczFGMlla);dappend(1);evreal(kiwi-ev:div);qreal(div|id=rVpseTyvMTxLms+);geom(0,10);sreal(bf797060cfda59d260e4f9be8bfb48c4281ac76ab4fcf982e42529ec7bfe5a76);cadd(MkFxTEM5c0pCNHY=);or(3621764315);shr(15901358);dserialize(aWQ9clZwc2VUeXZNVHhMbXMr);dappend(1);u8rot(0);dparent(1);dcreate(MVdiRXN3L1hhbEpHUlJQ);u8w(0);ddispatch(1);dcreate(ZFNIazI0RkFsM1diODVDMw==);dget();dgetd();shr(57671);mul(3922108062)',
            'expected' => 'valid',
        ],

        [
            'name' => 'v2-valid',
            'version' => 2,
            'program' => 'AQVsb2dpbgxsb2dpbi1hY3Rpb24CEhCNDFFpRjBZNTJyeGlsLxcJVHpOaWpvNHppEgjXIQxRaUYwWTUycnhpbC8YChgJDHIfDFFpRjBZNTJyeGlsLxwMUWlGMFk1MnJ4aWwvFHUZFgg/Y1l2KUZwWgjBAHQ4GXzGbcEkCxYEK3K7YCU/jIESBS5wXzlYoYg7',
            'trace' => 'dcreate(UWlGMFk1MnJ4aWwv);cadd(VHpOaWpvNHpp);dappend(1);u8c(0);obs(24,10);u8r(10);u8w(124);evreal(kiwi-ev:div);qreal(div|id=QiF0Y52rxil/);dget();dparent(1);dgetd();u8c(0);add(983947936);u8rot(0);and(556959744);dappend(1);or(2129780539)',
            'expected' => 'valid',
        ],

        [
            'name' => 'v3-valid',
            'version' => 3,
            'program' => 'AQVsb2dpbgxsb2dpbi1hY3Rpb24DFBDBDnVPWlRTamU1a2ltTk9vFwU4QWF1TBIQkQ9YeWJUOTdpQXI4bWEvN3AVDHh6MnJmcWNqZzFqcgNXcyUSCNIhDnVPWlRTamU1a2ltTk9vIAogCebGHQ51T1pUU2plNWtpbU5PbyIPWHliVDk3aUFyOG1hLzdwIBwOdU9aVFNqZTVraW1OT28YCFRuRHZOUG9sFQZ4bWg3Nm4XKVghWD44OXY9K1s1bH0wUjtOX1AkQl8AZCz2ep3N8tYJAYwTC1Q3R0h3dEcxYUV0EVMRM1k+UyJVXWgkPDFaWDdbe0s=',
            'trace' => 'dcreate(dU9aVFNqZTVraW1OT28=);cadd(OEFhdUw=);dappend(1);dcreate(WHliVDk3aUFyOG1hLzdw);dset(eHoycmZxY2pnMWpy);dappend(1);u8c(0);obs(32,10);u8r(10);u8w(208);geom(0,10);dsib(2);sreal(dcaf3e3e55c8ac4d0c5d0efa52c20026312f19884fef74774f9124b6ab0dd18f);qreal(none);ccont(0);dset(eG1oNzZu);add(33220944);u8w(92);dqsel(0);dattr(dGl0bGU=)',
            'expected' => 'valid',
        ],

        [
            'name' => 'v4-valid',
            'version' => 4,
            'program' => 'AQVsb2dpbgxsb2dpbi1hY3Rpb24EExCjDWxzM0JqblJlVG92Rk4VBHh6b2EcR0EvalpQVmZWSi9DZUsoYVlvPUIzJnNbaUBZYhIQuQdXTXZ2SXZXEfUDPHdLEiPWDGhKMTlmOGtDeW9keCN8B2JHT0NtU1IIYCENbHMzQmpuUmVUb3ZGThMKEwlW3B8NbHMzQmpuUmVUb3ZGTiIHV012dkl2VyQHYkdPQ21TUh8NbHMzQmpuUmVUb3ZGTiAgAHgKyiaEMcDn',
            'trace' => 'dcreate(bHMzQmpuUmVUb3ZGTg==);dset(eHpvYQ==);dappend(1);dcreate(V012dkl2Vw==);dattr(ZGF0YS1raXdp);dappend(1);dchild(aEoxOWY4a0N5b2R4);dchild(YkdPQ21TUg==);u8c(0);obs(19,10);u8r(10);u8w(230);evreal(kiwi-ev:span);dsib(2);ddepth(2);evreal(kiwi-ev:span);sreal(cd9e8bb6200d6f874d25e6c520fcf5355622e04f4fb2f9140f48775369a8decb);sreal(cd9e8bb6200d6f874d25e6c520fcf5355622e04f4fb2f9140f48775369a8decb);add(4231826189)',
            'expected' => 'valid',
        ],

        [
            'name' => 'v5-valid',
            'version' => 5,
            'program' => 'AQVsb2dpbgxsb2dpbi1hY3Rpb24FGBCuB1JVL0ZoMlEVA3h5ZRhbcHReK0AkOTwwKmRPdFkvaE4jTld6WVcSEDIHWkdpZEZ5UxEIED5kPzI2QkFwYGpCUXkqVkESI7kFSWxlZlojLgVHeUV3aQjHIQdSVS9GaDJRAAoACW4GHwdSVS9GaDJRIgdaR2lkRnlTJAVHeUV3aSYEeHorTxQnB1pHaWRGeVMOCg4qKxoiMGhZRTBFSCMoJS9qdVQ0T1Aie2FjPllULAwgIB4YAAQwO2IhdS8Ddg==',
            'trace' => 'dcreate(UlUvRmgyUQ==);dset(eHll);dappend(1);dcreate(WkdpZEZ5Uw==);dattr(dGl0bGU=);dappend(1);dchild(SWxlZlo=);dchild(R3lFd2k=);u8c(0);obs(0,10);u8r(10);u8w(10);evreal(kiwi-ev:span);dsib(2);ddepth(2);dclone(1);drepar(2);u8r(2);durlc(e76cac2dfcc313d58bb0f731c433badf0651978a1769007ff3c1ab62cf59fee7);dmutate(26);sreal(9b5d5921b44c155a1158e759306b670558b30865e11e604bbd721f255c3e6c0c);sreal(9b5d5921b44c155a1158e759306b670558b30865e11e604bbd721f255c3e6c0c);point(div);and(808124960)',
            'expected' => 'valid',
        ],

        [
            'name' => 'v5-fragment-append',
            'version' => 5,
            'program' => 'AQVsb2dpbgxsb2dpbi1hY3Rpb24FCBAABEFBQUERAAFaEhAABEJCQkISCAAKACUAAA==',
            'trace' => 'dcreate(QUFBQQ==);dattr(ZGF0YS1raXdp);dappend(1);dcreate(QkJCQg==);dappend(1);u8c(0);u8r(0);dfrag(1)',
            'expected' => 'valid',
        ],

        [
            'name' => 'v5-urlc-forged',
            'version' => 5,
            'program' => 'AQVsb2dpbgxsb2dpbi1hY3Rpb24FGBCuB1JVL0ZoMlEVA3h5ZRhbcHReK0AkOTwwKmRPdFkvaE4jTld6WVcSEDIHWkdpZEZ5UxEIED5kPzI2QkFwYGpCUXkqVkESI7kFSWxlZlojLgVHeUV3aQjHIQdSVS9GaDJRAAoACW4GHwdSVS9GaDJRIgdaR2lkRnlTJAVHeUV3aSYEeHorTxQnB1pHaWRGeVMOCg4qKxoiMGhZRTBFSCMoJS9qdVQ0T1Aie2FjPllULAwgIB4YAAQwO2IhdS8Ddg==',
            'trace' => 'dcreate(UlUvRmgyUQ==);dset(eHll);dappend(1);dcreate(WkdpZEZ5Uw==);dattr(dGl0bGU=);dappend(1);dchild(SWxlZlo=);dchild(R3lFd2k=);u8c(0);obs(0,10);u8r(10);u8w(10);evreal(kiwi-ev:span);dsib(2);ddepth(2);dclone(1);drepar(2);u8r(2);durlc(000000000000000000000000000000000000000000000000000000000000000g);dmutate(26);sreal(9b5d5921b44c155a1158e759306b670558b30865e11e604bbd721f255c3e6c0c);sreal(9b5d5921b44c155a1158e759306b670558b30865e11e604bbd721f255c3e6c0c);point(div);and(808124960)',
            'expected' => 'execution_mismatch',
        ],

        [
            'name' => 'op-count-too-large',
            'version' => 1,
            'program' => 'AQVsb2dpbgxsb2dpbi1hY3Rpb24B/xA4D3JWcHNlVHl2TVR4TG1zKxcJVXJYczFGMllaEh8PclZwc2VUeXZNVHhMbXMrHA9yVnBzZVR5dk1UeExtcysdD3JWcHNlVHl2TVR4TG1zKyAXCzJBcUxDOXNKQjR2BZbLHEPX1bDYB/KirhATuo0oGxILsBkQUA8xV2JFc3cvWGFsSkdSUlAJt5MaEOAQZFNIazI0RkFsM1diODVDMxQkFgVySmkjWQdwo5mMcPosjwLkcZPOX9oyWQ==',
            'trace' => 'dcreate(clZwc2VUeXZNVHhMbXMr);cadd(VXJYczFGMlla);dappend(1);evreal(kiwi-ev:div);qreal(div|id=rVpseTyvMTxLms+);geom(0,10);sreal(bf797060cfda59d260e4f9be8bfb48c4281ac76ab4fcf982e42529ec7bfe5a76);cadd(MkFxTEM5c0pCNHY=);or(3621764315);shr(15901358);dserialize(aWQ9clZwc2VUeXZNVHhMbXMr);dappend(1);u8rot(0);dparent(1);dcreate(MVdiRXN3L1hhbEpHUlJQ);u8w(0);ddispatch(1);dcreate(ZFNIazI0RkFsM1diODVDMw==);dget();dgetd();shr(57671);mul(3922108062)',
            'expected' => 'malformed',
        ],

        [
            'name' => 'trailing-bytes',
            'version' => 1,
            'program' => 'AQVsb2dpbgxsb2dpbi1hY3Rpb24BFhA4D3JWcHNlVHl2TVR4TG1zKxcJVXJYczFGMllaEh8PclZwc2VUeXZNVHhMbXMrHA9yVnBzZVR5dk1UeExtcysdD3JWcHNlVHl2TVR4TG1zKyAXCzJBcUxDOXNKQjR2BZbLHEPX1bDYB/KirhATuo0oGxILsBkQUA8xV2JFc3cvWGFsSkdSUlAJt5MaEOAQZFNIazI0RkFsM1diODVDMxQkFgVySmkjWQdwo5mMcPosjwLkcZPOX9oyWQA=',
            'trace' => 'dcreate(clZwc2VUeXZNVHhMbXMr);cadd(VXJYczFGMlla);dappend(1);evreal(kiwi-ev:div);qreal(div|id=rVpseTyvMTxLms+);geom(0,10);sreal(bf797060cfda59d260e4f9be8bfb48c4281ac76ab4fcf982e42529ec7bfe5a76);cadd(MkFxTEM5c0pCNHY=);or(3621764315);shr(15901358);dserialize(aWQ9clZwc2VUeXZNVHhMbXMr);dappend(1);u8rot(0);dparent(1);dcreate(MVdiRXN3L1hhbEpHUlJQ);u8w(0);ddispatch(1);dcreate(ZFNIazI0RkFsM1diODVDMw==);dget();dgetd();shr(57671);mul(3922108062)',
            'expected' => 'malformed',
        ],

        [
            'name' => 'bad-op-version',
            'version' => 2,
            'program' => 'AQVsb2dpbgxsb2dpbi1hY3Rpb24JEhCNDFFpRjBZNTJyeGlsLxcJVHpOaWpvNHppEgjXIQxRaUYwWTUycnhpbC8YChgJDHIfDFFpRjBZNTJyeGlsLxwMUWlGMFk1MnJ4aWwvFHUZFgg/Y1l2KUZwWgjBAHQ4GXzGbcEkCxYEK3K7YCU/jIESBS5wXzlYoYg7',
            'trace' => 'dcreate(UWlGMFk1MnJ4aWwv);cadd(VHpOaWpvNHpp);dappend(1);u8c(0);obs(24,10);u8r(10);u8w(124);evreal(kiwi-ev:div);qreal(div|id=QiF0Y52rxil/);dget();dparent(1);dgetd();u8c(0);add(983947936);u8rot(0);and(556959744);dappend(1);or(2129780539)',
            'expected' => 'malformed',
        ],

        [
            'name' => 'bad-op-version-down',
            'version' => 4,
            'program' => 'AQVsb2dpbgxsb2dpbi1hY3Rpb24DExCjDWxzM0JqblJlVG92Rk4VBHh6b2EcR0EvalpQVmZWSi9DZUsoYVlvPUIzJnNbaUBZYhIQuQdXTXZ2SXZXEfUDPHdLEiPWDGhKMTlmOGtDeW9keCN8B2JHT0NtU1IIYCENbHMzQmpuUmVUb3ZGThMKEwlW3B8NbHMzQmpuUmVUb3ZGTiIHV012dkl2VyQHYkdPQ21TUh8NbHMzQmpuUmVUb3ZGTiAgAHgKyiaEMcDn',
            'trace' => 'dcreate(bHMzQmpuUmVUb3ZGTg==);dset(eHpvYQ==);dappend(1);dcreate(V012dkl2Vw==);dattr(ZGF0YS1raXdp);dappend(1);dchild(aEoxOWY4a0N5b2R4);dchild(YkdPQ21TUg==);u8c(0);obs(19,10);u8r(10);u8w(230);evreal(kiwi-ev:span);dsib(2);ddepth(2);evreal(kiwi-ev:span);sreal(cd9e8bb6200d6f874d25e6c520fcf5355622e04f4fb2f9140f48775369a8decb);sreal(cd9e8bb6200d6f874d25e6c520fcf5355622e04f4fb2f9140f48775369a8decb);add(4231826189)',
            'expected' => 'malformed',
        ],

        [
            'name' => 'overlong-operand',
            'version' => 1,
            'program' => 'AQVsb2dpbgxsb2dpbi1hY3Rpb24BCBISEhISEhIMEQ==',
            'trace' => 'dcreate(clZwc2VUeXZNVHhMbXMr);cadd(VXJYczFGMlla);dappend(1);evreal(kiwi-ev:div);qreal(div|id=rVpseTyvMTxLms+);geom(0,10);sreal(bf797060cfda59d260e4f9be8bfb48c4281ac76ab4fcf982e42529ec7bfe5a76);cadd(MkFxTEM5c0pCNHY=);or(3621764315);shr(15901358);dserialize(aWQ9clZwc2VUeXZNVHhMbXMr);dappend(1);u8rot(0);dparent(1);dcreate(MVdiRXN3L1hhbEpHUlJQ);u8w(0);ddispatch(1);dcreate(ZFNIazI0RkFsM1diODVDMw==);dget();dgetd();shr(57671);mul(3922108062)',
            'expected' => 'malformed',
        ],

        [
            'name' => 'sibling-index-forged',
            'version' => 3,
            'program' => 'AQVsb2dpbgxsb2dpbi1hY3Rpb24DFBDBDnVPWlRTamU1a2ltTk9vFwU4QWF1TBIQkQ9YeWJUOTdpQXI4bWEvN3AVDHh6MnJmcWNqZzFqcgNXcyUSCNIhDnVPWlRTamU1a2ltTk9vIAogCebGHQ51T1pUU2plNWtpbU5PbyIPWHliVDk3aUFyOG1hLzdwIBwOdU9aVFNqZTVraW1OT28YCFRuRHZOUG9sFQZ4bWg3Nm4XKVghWD44OXY9K1s1bH0wUjtOX1AkQl8AZCz2ep3N8tYJAYwTC1Q3R0h3dEcxYUV0EVMRM1k+UyJVXWgkPDFaWDdbe0s=',
            'trace' => 'dcreate(dU9aVFNqZTVraW1OT28=);cadd(OEFhdUw=);dappend(1);dcreate(WHliVDk3aUFyOG1hLzdw);dset(eHoycmZxY2pnMWpy);dappend(1);u8c(0);obs(32,10);u8r(10);u8w(208);geom(0,10);dsib(3);sreal(dcaf3e3e55c8ac4d0c5d0efa52c20026312f19884fef74774f9124b6ab0dd18f);qreal(none);ccont(0);dset(eG1oNzZu);add(33220944);u8w(92);dqsel(0);dattr(dGl0bGU=)',
            'expected' => 'execution_mismatch',
        ],

        [
            'name' => 'observe-out-of-bounds',
            'version' => 2,
            'program' => 'AQVsb2dpbgxsb2dpbi1hY3Rpb24CEhCNDFFpRjBZNTJyeGlsLxcJVHpOaWpvNHppEgjXIQxRaUYwWTUycnhpbC8YChgJDHIfDFFpRjBZNTJyeGlsLxwMUWlGMFk1MnJ4aWwvFHUZFgg/Y1l2KUZwWgjBAHQ4GXzGbcEkCxYEK3K7YCU/jIESBS5wXzlYoYg7',
            'trace' => 'dcreate(UWlGMFk1MnJ4aWwv);cadd(VHpOaWpvNHpp);dappend(1);u8c(0);obs(24,256);u8r(10);u8w(124);evreal(kiwi-ev:div);qreal(div|id=QiF0Y52rxil/);dget();dparent(1);dgetd();u8c(0);add(983947936);u8rot(0);and(556959744);dappend(1);or(2129780539)',
            'expected' => 'execution_mismatch',
        ],

        [
            'name' => 'observe-out-of-bounds-dst',
            'version' => 2,
            'program' => 'AQVsb2dpbgxsb2dpbi1hY3Rpb24CEhCNDFFpRjBZNTJyeGlsLxcJVHpOaWpvNHppEgjXIQxRaUYwWTUycnhpbC8YChgJDHIfDFFpRjBZNTJyeGlsLxwMUWlGMFk1MnJ4aWwvFHUZFgg/Y1l2KUZwWgjBAHQ4GXzGbcEkCxYEK3K7YCU/jIESBS5wXzlYoYg7',
            'trace' => 'dcreate(UWlGMFk1MnJ4aWwv);cadd(VHpOaWpvNHpp);dappend(1);u8c(0);obs(99,10);u8r(10);u8w(124);evreal(kiwi-ev:div);qreal(div|id=QiF0Y52rxil/);dget();dparent(1);dgetd();u8c(0);add(983947936);u8rot(0);and(556959744);dappend(1);or(2129780539)',
            'expected' => 'execution_mismatch',
        ],

        [
            'name' => 'duplicate-entry',
            'version' => 1,
            'program' => 'AQVsb2dpbgxsb2dpbi1hY3Rpb24BFhA4D3JWcHNlVHl2TVR4TG1zKxcJVXJYczFGMllaEh8PclZwc2VUeXZNVHhMbXMrHA9yVnBzZVR5dk1UeExtcysdD3JWcHNlVHl2TVR4TG1zKyAXCzJBcUxDOXNKQjR2BZbLHEPX1bDYB/KirhATuo0oGxILsBkQUA8xV2JFc3cvWGFsSkdSUlAJt5MaEOAQZFNIazI0RkFsM1diODVDMxQkFgVySmkjWQdwo5mMcPosjwLkcZPOX9oyWQ==',
            'trace' => 'dcreate(clZwc2VUeXZNVHhMbXMr);cadd(VXJYczFGMlla);dappend(1);dappend(1);evreal(kiwi-ev:div);qreal(div|id=rVpseTyvMTxLms+);geom(0,10);sreal(bf797060cfda59d260e4f9be8bfb48c4281ac76ab4fcf982e42529ec7bfe5a76);cadd(MkFxTEM5c0pCNHY=);or(3621764315);shr(15901358);dserialize(aWQ9clZwc2VUeXZNVHhMbXMr);dappend(1);dappend(1);u8rot(0);dparent(1);dcreate(MVdiRXN3L1hhbEpHUlJQ);u8w(0);ddispatch(1);dcreate(ZFNIazI0RkFsM1diODVDMw==);dget();dgetd();shr(57671);mul(3922108062)',
            'expected' => 'execution_mismatch',
        ],

        [
            'name' => 'missing-entry',
            'version' => 2,
            'program' => 'AQVsb2dpbgxsb2dpbi1hY3Rpb24CEhCNDFFpRjBZNTJyeGlsLxcJVHpOaWpvNHppEgjXIQxRaUYwWTUycnhpbC8YChgJDHIfDFFpRjBZNTJyeGlsLxwMUWlGMFk1MnJ4aWwvFHUZFgg/Y1l2KUZwWgjBAHQ4GXzGbcEkCxYEK3K7YCU/jIESBS5wXzlYoYg7',
            'trace' => 'dcreate(UWlGMFk1MnJ4aWwv);cadd(VHpOaWpvNHpp);dappend(1);u8c(0);u8r(10);u8w(124);evreal(kiwi-ev:div);qreal(div|id=QiF0Y52rxil/);dget();dparent(1);dgetd();u8c(0);add(983947936);u8rot(0);and(556959744);dappend(1);or(2129780539)',
            'expected' => 'execution_mismatch',
        ],

        [
            'name' => 'appended-garbage',
            'version' => 4,
            'program' => 'AQVsb2dpbgxsb2dpbi1hY3Rpb24EExCjDWxzM0JqblJlVG92Rk4VBHh6b2EcR0EvalpQVmZWSi9DZUsoYVlvPUIzJnNbaUBZYhIQuQdXTXZ2SXZXEfUDPHdLEiPWDGhKMTlmOGtDeW9keCN8B2JHT0NtU1IIYCENbHMzQmpuUmVUb3ZGThMKEwlW3B8NbHMzQmpuUmVUb3ZGTiIHV012dkl2VyQHYkdPQ21TUh8NbHMzQmpuUmVUb3ZGTiAgAHgKyiaEMcDn',
            'trace' => 'dcreate(bHMzQmpuUmVUb3ZGTg==);dset(eHpvYQ==);dappend(1);dcreate(V012dkl2Vw==);dattr(ZGF0YS1raXdp);dappend(1);dchild(aEoxOWY4a0N5b2R4);dchild(YkdPQ21TUg==);u8c(0);obs(19,10);u8r(10);u8w(230);evreal(kiwi-ev:span);dsib(2);ddepth(2);evreal(kiwi-ev:span);sreal(cd9e8bb6200d6f874d25e6c520fcf5355622e04f4fb2f9140f48775369a8decb);sreal(cd9e8bb6200d6f874d25e6c520fcf5355622e04f4fb2f9140f48775369a8decb);add(4231826189);add(0)',
            'expected' => 'execution_mismatch',
        ],

        [
            'name' => 'appended-garbage-raw',
            'version' => 4,
            'program' => 'AQVsb2dpbgxsb2dpbi1hY3Rpb24EExCjDWxzM0JqblJlVG92Rk4VBHh6b2EcR0EvalpQVmZWSi9DZUsoYVlvPUIzJnNbaUBZYhIQuQdXTXZ2SXZXEfUDPHdLEiPWDGhKMTlmOGtDeW9keCN8B2JHT0NtU1IIYCENbHMzQmpuUmVUb3ZGThMKEwlW3B8NbHMzQmpuUmVUb3ZGTiIHV012dkl2VyQHYkdPQ21TUh8NbHMzQmpuUmVUb3ZGTiAgAHgKyiaEMcDn',
            'trace' => 'dcreate(bHMzQmpuUmVUb3ZGTg==);dset(eHpvYQ==);dappend(1);dcreate(V012dkl2Vw==);dattr(ZGF0YS1raXdp);dappend(1);dchild(aEoxOWY4a0N5b2R4);dchild(YkdPQ21TUg==);u8c(0);obs(19,10);u8r(10);u8w(230);evreal(kiwi-ev:span);dsib(2);ddepth(2);evreal(kiwi-ev:span);sreal(cd9e8bb6200d6f874d25e6c520fcf5355622e04f4fb2f9140f48775369a8decb);sreal(cd9e8bb6200d6f874d25e6c520fcf5355622e04f4fb2f9140f48775369a8decb);add(4231826189)garbage',
            'expected' => 'execution_mismatch',
        ],
    ];

    public function testCorpusVerdictsMatchTheExpectedClassifications(): void
    {
        $manifest = $this->manifest();
        $maxVersion = $manifest['max_execution_version'];
        self::assertSame(5, $maxVersion, 'the manifest register ceiling at HEAD');

        $cases = self::CORPUS;
        self::assertCount(19, $cases, 'the embedded corpus is pinned to 19 cases');
        foreach ($cases as $case) {
            $version = $case['version'];
            self::assertGreaterThanOrEqual(1, $version, $case['name'].' version below the floor');
            self::assertLessThanOrEqual($maxVersion, $version, $case['name'].' version above the manifest ceiling');

            $got = $this->verdict($case['program'], $case['trace']);
            self::assertSame(
                $case['expected'],
                $got,
                sprintf('case %s: expected %s, PHP decode/verify says %s', $case['name'], $case['expected'], $got),
            );
            if ($got === 'valid') {
                $digestA = ExecutionChallengeGenerator::digestOverTrace($case['program'], self::NONCE, $case['trace']);
                $digestB = ExecutionChallengeGenerator::digestOverTrace($case['program'], self::NONCE, $case['trace']);
                self::assertNotNull($digestA, $case['name'].': a valid trace must digest');
                self::assertSame($digestA, $digestB, $case['name'].': the digest is deterministic');
                self::assertSame(1, preg_match('/^[0-9a-f]{64}$/D', (string) $digestA), $case['name'].': the digest is 64 lowercase hex');
                self::assertSame(
                    $case['version'],
                    ExecutionChallengeGenerator::decode($case['program'])['op_version'],
                    $case['name'].': the decoded program declares its case version',
                );
            }
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function manifest(): array
    {
        $path = \dirname(__DIR__).'/../../protocol/execution-v1.json';
        if (!is_file($path)) {
            self::markTestSkipped('execution-v1.json not present (repo layout expected at protocol/)');
        }
        $manifest = json_decode((string) file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($manifest);

        return $manifest;
    }

    /**
     * The decode/verify verdict of one corpus case: malformed when the
     * program does not parse, execution_mismatch when the trace is not
     * a valid execution of the parsed program, valid otherwise. Mirrors
     * the Rust companion verdict exactly.
     */
    private function verdict(string $program, string $trace): string
    {
        if (ExecutionChallengeGenerator::decode($program) === null) {
            return 'malformed';
        }

        return ExecutionChallengeGenerator::verifyExecutedTrace($program, self::NONCE, $trace) === null
            ? 'execution_mismatch'
            : 'valid';
    }
}
