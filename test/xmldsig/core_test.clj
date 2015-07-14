(ns xmldsig.core-test
  (:use clojure.test)
  (:require [xmldsig.core :refer :all])
  (:import (java.io FileNotFoundException)
           (java.security.cert X509Certificate)))


(deftest load-certificate-test
  (is (thrown? FileNotFoundException (load-certificate "")))
  (is (instance? X509Certificate (load-certificate "test-resources/test-user-cert.pem"))))

