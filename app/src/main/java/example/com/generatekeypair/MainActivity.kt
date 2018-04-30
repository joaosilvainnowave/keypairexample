package example.com.generatekeypair

import android.support.v7.app.AppCompatActivity
import android.os.Bundle
import android.security.keystore.KeyProperties
import android.security.keystore.KeyGenParameterSpec
import android.util.Log
import java.security.*
import java.security.spec.RSAKeyGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec.F4
import kotlinx.android.synthetic.main.activity_main.*


class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
    }

    override fun onResume() {
        super.onResume()

        btn_generate.setOnClickListener {
            val keyPair = generateKeyPair()
            if (keyPair != null){
                Log.d("ACT", "OK")
            } else {
                Log.d("ACT", "ERROR")
            }
        }
    }

    private fun generateKeyPair() : KeyPair? {
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
            keyPairGenerator.initialize(
                    KeyGenParameterSpec.Builder(
                            "ALIAS",
                            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                            .setAlgorithmParameterSpec(RSAKeyGenParameterSpec(1024, F4))
                            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                            .setDigests(KeyProperties.DIGEST_SHA256,
                                    KeyProperties.DIGEST_SHA384,
                                    KeyProperties.DIGEST_SHA512)
                            .setUserAuthenticationRequired(false)
                            .build())
            return keyPairGenerator.generateKeyPair()

        } catch (e: NoSuchProviderException) {
            throw RuntimeException(e)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw RuntimeException(e)
        }

    }
}
