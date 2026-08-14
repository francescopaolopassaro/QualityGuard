import kotlin.system.exitProcess
import java.util.Random

fun main(user: String) {
    val r = Random()
    Runtime.getRuntime().exec(user)
    exitProcess(0)
    val secret = "s3cr3t"
}