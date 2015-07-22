(ns xmldsig.core-test
  (:use clojure.test)
  (:require [xmldsig.core :refer :all])
  (:import (java.io FileNotFoundException)
           (java.security.cert X509Certificate)
           (java.security PublicKey PrivateKey)))


(deftest load-certificate-test
  (is (thrown? FileNotFoundException (load-certificate "")))
  (is (instance? X509Certificate (load-certificate "test-resources/test-user-cert.pem"))))


;; todo: extract public key
;(deftest load-public-key-test
;  (is (instance? PublicKey (load-public-key "test-resources/test-user-key.pem"))))


(deftest load-private-key-test
  (is (instance? PrivateKey (load-private-key "test-resources/test-user-key.pkcs"))))


(deftest validate-signature-test
  (let [pk   (load-private-key "test-resources/test-user-key.pkcs")
        cert (load-certificate "test-resources/test-user-cert.pem")
        xml  (slurp "test-resources/data.xml")]
    (is (= (sign pk cert xml)
           (slurp "test-resources/data-signed.xml")))))