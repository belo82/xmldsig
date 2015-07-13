package xmldsig;

import javax.xml.crypto.*;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import java.security.Key;
import java.security.cert.X509Certificate;

/**
 * Source code copied from: <a href="http://www.oracle.com/technetwork/articles/javase/dig-signature-api-140772.html">Programming With the Java XML Digital Signature API</a>
 * <p/>
 * This is a very simple implementation of a <code>KeySelector</code> that returns the public key from the first X.509 certificate it finds in the <code>X509Data</code>.
 * <p/>
 * It is for demonstration purposes only and should not be used in real-world applications. A more complete X.509 key selector
 * implementation would check other types of <code>X509Data</code> and establish trust in the validation key by using a keystore of trusted keys,
 * or by finding and validating a certificate chain from a trust anchor to the certificate containing the public key.
 * <p/>
 * See the Java PKI Programmer's Guide for more information about trust anchors and Java APIs that you can use to establish trust in keys.
 */
public class X509KeySelector extends KeySelector {

    public KeySelectorResult select(KeyInfo keyInfo, KeySelector.Purpose purpose,
                                    AlgorithmMethod method, XMLCryptoContext context) throws KeySelectorException {

        final X509Certificate cert = findCertificate(keyInfo);

        if (cert != null) {
            return new KeySelectorResult() {
                @Override
                public Key getKey() {
                    return cert.getPublicKey();
                }
            };
        } else {
            throw new KeySelectorException("No key found!");
        }
    }

    static boolean algEquals(String algURI, String algName) {
        return ((algName.equalsIgnoreCase("DSA") && algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1))
                || (algName.equalsIgnoreCase("RSA") && algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1)));
    }

    public X509Certificate findCertificate(KeyInfo keyInfo) {

        for (Object o1 : keyInfo.getContent()) {
            XMLStructure info = (XMLStructure) o1;
            if (!(info instanceof X509Data))
                continue;
            X509Data x509Data = (X509Data) info;

            for (Object o : x509Data.getContent()) {
                if (!(o instanceof X509Certificate))
                    continue;

                X509Certificate cert = (X509Certificate) o;
                // Make sure the algorithm is compatible with the method.
                // todo: read algorithm name from <Signature>
//                if (algEquals(method.getAlgorithm(), cert.getPublicKey().getAlgorithm())) {
//                    return cert;
//                }
                return cert;
            }
        }
        return null;
    }
}
