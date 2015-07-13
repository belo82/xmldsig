(ns xmldsig.xml
  (:require [clojure.java.io :as io])
  (:import [javax.xml.transform.stream StreamResult]
           [javax.xml.transform.dom DOMSource]
           [java.io StringWriter InputStream]
           [javax.xml.transform Transformer TransformerFactory]
           [javax.xml.soap Node]
           [org.w3c.dom Document]
           [javax.xml.parsers DocumentBuilderFactory DocumentBuilder]))


(defn- ^InputStream str->is
  [^String string]
  (-> string .getBytes (io/input-stream)))


(defn serialise
  "Serialises XML object into string"
  [^Node xml]
  (let [^TransformerFactory tf (TransformerFactory/newInstance)
        ^Transformer trans (.newTransformer tf)

        swriter (StringWriter.)]
    (.transform trans (DOMSource. xml) (StreamResult. swriter))
    (.toString swriter)))


(defn ^Document parse
  [^String xml-string]
  (let [doc-builder-factory (doto
                              (DocumentBuilderFactory/newInstance)
                              (.setNamespaceAware true))
        xml-is (str->is xml-string)]
    (-> doc-builder-factory
        ^DocumentBuilder .newDocumentBuilder
        (.parse xml-is))))
