(ns xmldsig.core
  (:import [javax.xml.parsers DocumentBuilderFactory DocumentBuilder]
           [javax.xml.crypto.dsig.dom DOMSignContext DOMValidateContext]
           [javax.xml.crypto.dsig XMLSignatureFactory Transform DigestMethod Reference SignedInfo CanonicalizationMethod SignatureMethod XMLSignature]
           [java.util Collections ArrayList HashSet]
           [javax.xml.crypto.dsig.spec TransformParameterSpec C14NMethodParameterSpec]
           [java.io StringWriter InputStream]
           [org.w3c.dom Document NodeList]
           [javax.xml.crypto.dsig.keyinfo KeyInfoFactory KeyInfo X509Data]
           [javax.xml.transform TransformerFactory Transformer]
           [javax.xml.transform.dom DOMSource]
           [javax.xml.transform.stream StreamResult]
           [java.security KeyFactory PrivateKey PublicKey Key]
           [java.security.spec PKCS8EncodedKeySpec]
           [java.security.cert CertificateFactory Certificate X509Certificate X509CertSelector TrustAnchor PKIXBuilderParameters CertPathBuilder]
           [javax.xml.crypto KeySelector]
           [xmldsig X509KeySelector])
  (require [clojure.java.io :as io]
           [clojure.tools.logging :refer [debug info warn error]]))


(declare load-certificate)

(defn- ^InputStream str->is
  [^String string]
  (-> string .getBytes (io/input-stream)))


(defn- ^Document parse-xml-string
  [xml-string]
  (let [doc-builder-factory (doto
                              (DocumentBuilderFactory/newInstance)
                              (.setNamespaceAware true))
        xml-is (str->is xml-string)]
    (-> doc-builder-factory
        ^DocumentBuilder .newDocumentBuilder
        (.parse xml-is))))


(defn- serialise
  [doc]
  (let [^TransformerFactory tf (TransformerFactory/newInstance)
        ^Transformer trans (.newTransformer tf)

        swriter (StringWriter.)]
    (.transform trans (DOMSource. doc) (StreamResult. swriter))
    (.toString swriter)))


(defn- create-x509-data                                     ;; TODO possible options what to include in X.509 data
  [^KeyInfoFactory kif ^X509Certificate cert]
  (let [x509-content (doto (ArrayList.)
                       (.add (.. cert getSubjectX500Principal getName))
                       (.add cert))]

    (.newX509Data kif x509-content)))


(defn sign-xml
  ;; TODO: add option to attach/not to attach certificate to the signature
  ;; TODO: provide optional parameter with configuration map (signature method, canonicalization method, ...)
  "Signs XML document using the given private key and attaching given public key or public key and X.509 certificate if certificate is provided"
  [^PrivateKey private-key ^X509Certificate cert ^String xml-string ]
  (let [doc (parse-xml-string xml-string)
        public-key (.getPublicKey cert)

        ^DOMSignContext dsc (DOMSignContext. private-key (.getDocumentElement doc))
        ^XMLSignatureFactory fac (XMLSignatureFactory/getInstance "DOM")

        ^TransformParameterSpec tps nil
        ref (cast Reference (.newReference fac
                              ""
                              (.newDigestMethod fac DigestMethod/SHA1 nil)
                              (Collections/singletonList
                                (.newTransform fac
                                  Transform/ENVELOPED
                                  tps))
                              nil nil))

        ^C14NMethodParameterSpec c14n-method nil
        si (cast SignedInfo
             (.newSignedInfo fac
               (.newCanonicalizationMethod fac
                 CanonicalizationMethod/INCLUSIVE_WITH_COMMENTS
                 c14n-method)
               (.newSignatureMethod fac SignatureMethod/RSA_SHA1 nil)
               (Collections/singletonList ref)))

        ^KeyInfoFactory kif (.getKeyInfoFactory fac)

        ; include either key or certificate, don't need to be both
        ;^KeyValue kv (.newKeyValue kif public-key)

        ^X509Data x509d (create-x509-data kif cert)

        ^ArrayList ki-items (doto (ArrayList.)
                              ;(.add kv)
                              (.add x509d))

        ^KeyInfo ki (.newKeyInfo kif ki-items)
        ^XMLSignature signature (.newXMLSignature fac si ki)]

    (.sign signature dsc)
    (serialise doc)))


(def ^HashSet get-trust-anchors
  (memoize
    #(let [^X509Certificate ca-cert (load-certificate (config :xmldsig :trusted-root-cert))]
      ;; This can be key store if more than one truted key needed
      (doto (HashSet.)
        (.add (TrustAnchor. ca-cert nil))))))


(defn- validate-certificate-path
  "Validates certification path. Returns true if certification path was bult successfully.
  If verification of any certificate in the chaing fails, function returns false."
  [^X509Certificate cert]
  (let [^X509CertSelector selector (doto (X509CertSelector.) (.setCertificate cert))

        ;; Also possible add all intermediates if certificatioin chaing is longer than 1
        ;; CertStoreParameters intermediates = new CollectionCertStoreParameters(listOfIntermediateCertificates)
        ;; params.addCertStore(CertStore.getInstance("Collection", intermediates));

        ^PKIXBuilderParameters params (doto
                                        (PKIXBuilderParameters. (get-trust-anchors) selector)
                                        (.setRevocationEnabled false))]
    (try
      (-> "PKIX"
          (CertPathBuilder/getInstance)
          (.build params)
          nil?
          not)
      (catch Throwable th (error th "Couldn't validate certificate path for certificate:" cert)))))


(defn- validate-signature
  "Validates signature on the XML string with key matching key-selector. If signature is valid, returns KeyInfo
  used for signature validation, otherwise nil"
  [xml-string ^KeySelector key-selector]
  (let [^Document doc (parse-xml-string xml-string)
        ^NodeList sig-elem-node-list (.getElementsByTagNameNS doc XMLSignature/XMLNS "Signature")]

    (when-let [signature-node (.item sig-elem-node-list 0)]
      (let [^XMLSignatureFactory fac (XMLSignatureFactory/getInstance "DOM")
            ^DOMValidateContext val-ctx (DOMValidateContext. key-selector signature-node)
            ^XMLSignature signature (.unmarshalXMLSignature fac val-ctx)

            valid (.validate signature val-ctx)]
        (if-not valid
          (do (warn "Signature failed core validation")
              (let [sv (-> signature .getSignatureValue (.validate val-ctx))]
                (warn "Signature validation status:" sv))
              (doseq [^Reference ref (-> signature .getSignedInfo .getReferences)]
                (let [ref-valid (.validate ref val-ctx)]
                  (warn "Reference URI" (str "'" (.getURI ref) "'") "validity status:" ref-valid))))
          (.getKeyInfo signature))))))


(defn validate
  "This is rather testing method than proper cert and PKI verification. Validates signature with the given validating-key.
  If no validating key is provided, it tries to read certificate from X509Data element nested in the document
  It doesn't do any PKI/Cert path/cert revokation validation and check"
  ([xml-string]
   (let [key-selector (X509KeySelector.)
         ^KeyInfo key-info (validate-signature xml-string key-selector)]
     (if key-info
       ;; document wasn't tampered and signature is valid.
       ;; Now, let's build certificate chain for signing certificate and validate it
       (validate-certificate-path (.findCertificate key-selector key-info))
       false)))

  ([xml-string ^Key validating-key]
   (validate-signature xml-string (KeySelector/singletonKeySelector validating-key))))


(defn- file->byte-array
  [file-path]
  (let [file       (io/file file-path)
        byte-array (byte-array (.length file))]
    (with-open [is (io/input-stream file)]
      (.read is byte-array))
    byte-array))


(defn ^PrivateKey load-private-key
  "Loads private key from a file. Default algorithm is RSA"
  ([file-path] (load-private-key "RSA" file-path))
  ([algorithm file-path]
   (->> file-path
     file->byte-array
     PKCS8EncodedKeySpec.
     (.generatePrivate
       (KeyFactory/getInstance algorithm)))))


(defn ^PrivateKey load-public-key
  "Loads public key from a file. Defaul algorithm is RSA"
  ([file-path] (load-private-key "RSA" file-path))
  ([algorithm file-path]
   (->> file-path
     file->byte-array
     PKCS8EncodedKeySpec.
     (.generatePublic
       (KeyFactory/getInstance algorithm)))))


(defn ^Certificate load-certificate
  ([file-path] (load-certificate "X.509" file-path))
  ([cert-type file-path]
   (->> file-path
     io/input-stream
     (.generateCertificate
       (CertificateFactory/getInstance cert-type)))))


(defn ^PublicKey read-pub-key
  "Reads public key from a certificate file. By default it uses X.509 certificate type"
  ([cert-path] (read-pub-key "X.509" cert-path))
  ([cert-type cert-path]
   (.getPublicKey (load-certificate cert-type cert-path))))