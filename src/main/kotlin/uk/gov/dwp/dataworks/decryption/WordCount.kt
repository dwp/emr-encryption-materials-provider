package uk.gov.dwp.dataworks.decryption

import org.apache.spark.sql.SparkSession

object WordCount {

    @JvmStatic
    fun main(args: Array<String>) {
            val spark = SparkSession.builder().appName("Simple Application")
            .getOrCreate()
        val logData = spark.read().textFile(args[0]).cache()

        val numAs = logData.filter({ s -> s.contains("a") }).count()
        val numBs = logData.filter({ s -> s.contains("b") }).count()

        println("Lines with a: $numAs, lines with b: $numBs")
        spark.stop()
    }
}
