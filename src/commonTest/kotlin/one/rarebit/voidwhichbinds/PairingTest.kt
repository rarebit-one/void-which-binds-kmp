package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Hex
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Golden vectors CAPTURED FROM void-which-binds-go's v2 pairing (`pairing.Commit` /
 * `pairing.Derive`) with fixed inputs — signing = 0x11×32, enc = 0x12×32 for the
 * initiator; signing = 0x21×32, enc = 0x22×32 for the responder; salt = 0x33×32.
 * These prove the Kotlin port is byte-identical to the Go side, which is the
 * whole point: a SAS or commitment that differs by one byte does not interoperate.
 */
class PairingTest {

    private fun rep(b: Int) = ByteArray(32) { b.toByte() }

    private val iSign = rep(0x11)
    private val iEnc = rep(0x12)
    private val rSign = rep(0x21)
    private val rEnc = rep(0x22)
    private val salt = rep(0x33)

    private val goldenInitCommit = "6df14752bdcc1e58d6a5eae2e7741c93b8729838cf94167b4095d881753ccf91"
    private val goldenRespCommit = "585754a70d9cf615c61fe4de37523f939749d39ce0f7d4b11baf777dc1cf7dcf"
    private val goldenSas = "8591300"
    private val goldenInitCommitEmptyEnc = "7bacd4d00d224212ae5094ae0f9fbcd10790dae5ed26295996b6a3830772545c"
    private val goldenSasEmptyEnc = "2393931"

    @Test
    fun commitMatchesVoidbindGo() {
        assertEquals(goldenInitCommit, Hex.encode(Pairing.commit(iSign, iEnc)))
        assertEquals(goldenRespCommit, Hex.encode(Pairing.commit(rSign, rEnc)))
    }

    @Test
    fun sasMatchesVoidbindGo() {
        val sas = Pairing.deriveSas(Pairing.Keys(iSign, iEnc), Pairing.Keys(rSign, rEnc), salt)
        assertEquals(goldenSas, sas)
        assertEquals(Pairing.DIGITS, sas.length)
    }

    @Test
    fun emptyEncryptionKeyIsBoundByItsAbsence() {
        assertEquals(goldenInitCommitEmptyEnc, Hex.encode(Pairing.commit(iSign)))
        val sas = Pairing.deriveSas(Pairing.Keys(iSign), Pairing.Keys(rSign), salt)
        assertEquals(goldenSasEmptyEnc, sas)
    }

    @Test
    fun openAcceptsTheCommittedKeysAndRejectsAnyChange() {
        val c = Pairing.commit(iSign, iEnc)
        assertTrue(Pairing.opens(c, iSign, iEnc), "the committed keys open the commitment")
        assertFalse(Pairing.opens(c, rSign, iEnc), "a swapped signing key does not open it")
        assertFalse(Pairing.opens(c, iSign, rEnc), "a swapped encryption key does not open it (v2)")
        assertFalse(Pairing.opens(c, iSign), "dropping the encryption key does not open it")
    }

    @Test
    fun substitutingEitherKeyChangesTheSas() {
        val honest = Pairing.deriveSas(Pairing.Keys(iSign, iEnc), Pairing.Keys(rSign, rEnc), salt)
        val swappedSign = Pairing.deriveSas(Pairing.Keys(rSign, iEnc), Pairing.Keys(rSign, rEnc), salt)
        val swappedEnc = Pairing.deriveSas(Pairing.Keys(iSign, rEnc), Pairing.Keys(rSign, rEnc), salt)
        assertFalse(honest == swappedSign, "substituting the initiator's signing key changes the SAS")
        assertFalse(honest == swappedEnc, "substituting the initiator's encryption key changes the SAS (v2)")
    }

    @Test
    fun refusesMalformedInput() {
        assertFailsWith<IllegalArgumentException> { Pairing.commit(ByteArray(20)) }
        assertFailsWith<IllegalArgumentException> {
            Pairing.deriveSas(Pairing.Keys(iSign, iEnc), Pairing.Keys(rSign, rEnc), ByteArray(8))
        }
        assertFailsWith<IllegalArgumentException> { Pairing.opens(ByteArray(10), iSign, iEnc) }
    }
}
