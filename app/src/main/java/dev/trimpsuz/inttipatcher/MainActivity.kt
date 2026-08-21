package dev.trimpsuz.inttipatcher

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import com.android.apksig.ApkSigner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileOutputStream
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal
import java.util.Collections
import java.util.Date
import java.util.zip.ZipFile
import java.util.zip.ZipEntry

private enum class InputMode { APK_PAIR, XAPK }

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent { AppTheme { MainScreen() } }
    }
}

@Composable
private fun AppTheme(content: @Composable () -> Unit) {
    val context = LocalContext.current
    val dark = isSystemInDarkTheme()
    val colorScheme = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
    } else if (dark) {
        darkColorScheme(
            primary = Color(0xFF9ECBFF),
            secondary = Color(0xFFB5C7DD),
            tertiary = Color(0xFF96CFFA),
            background = Color(0xFF111318),
            surface = Color(0xFF111318)
        )
    } else {
        lightColorScheme(
            primary = Color(0xFF0061A4),
            secondary = Color(0xFF535F70),
            tertiary = Color(0xFF00649A)
        )
    }
    MaterialTheme(colorScheme = colorScheme, content = content)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MainScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val scroll = rememberScrollState()

    var mode by remember { mutableStateOf(InputMode.APK_PAIR) }
    var baseUri by remember { mutableStateOf<Uri?>(null) }
    var splitUri by remember { mutableStateOf<Uri?>(null) }
    var xapkUri by remember { mutableStateOf<Uri?>(null) }
    var baseName by remember { mutableStateOf<String?>(null) }
    var splitName by remember { mutableStateOf<String?>(null) }
    var xapkName by remember { mutableStateOf<String?>(null) }
    var newPkg by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var patchedFile by remember { mutableStateOf<File?>(null) }
    val log = remember { mutableStateListOf<String>() }

    val patchData = remember {
        try {
            val json = context.assets.open("patch.json").readBytes().toString(Charsets.UTF_8)
            val root = JsonMin.obj(JsonMin.parse(json))
            val c = PatcherEngine.Config()
            c.originalPackage = JsonMin.str(root["package"])
            c.libEntry = JsonMin.str(root["libEntry"])
            c.libSha256 = JsonMin.str(root["libSha256"])
            c.removeManifestAttrs = JsonMin.arr(root["removeManifestAttrs"]).map { JsonMin.str(it) }.toTypedArray()
            c.patches = JsonMin.arr(root["patches"]).map { t ->
                val a = JsonMin.arr(t)
                longArrayOf(JsonMin.lng(a[0]), JsonMin.lng(a[1]), JsonMin.lng(a[2]))
            }
            Triple(c, JsonMin.str(root["versionName"]), JsonMin.lng(root["versionCode"]))
        } catch (_: Exception) {
            null
        }
    }
    val cfg = patchData?.first
    val cfgLabel = patchData?.let { "INTTI " + it.second + " (v" + it.third + ")" }
        ?: "Patch data failed to load!"

    fun logLine(s: String) {
        log.add(s)
        if (log.size > 400) log.removeAt(0)
    }

    fun toast(s: String) {
        Toast.makeText(context, s, Toast.LENGTH_LONG).show()
    }

    val basePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            baseUri = uri
            baseName = uri.lastPathSegment
            logLine("Base APK: " + uri.lastPathSegment)
        }
    }
    val splitPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            splitUri = uri
            splitName = uri.lastPathSegment
            logLine("Split APK: " + uri.lastPathSegment)
        }
    }
    val xapkPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            xapkUri = uri
            xapkName = uri.lastPathSegment
            logLine("XAPK: " + uri.lastPathSegment)
        }
    }

    fun installPrompt() {
        val f = patchedFile ?: return
        try {
            val uri = FileProvider.getUriForFile(context, "dev.trimpsuz.inttipatcher.fileprovider", f)
            val i = Intent(Intent.ACTION_VIEW)
            i.setDataAndType(uri, "application/vnd.android.package-archive")
            i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(i)
        } catch (e: Exception) {
            toast("Could not open the installer: " + e.message)
        }
    }

    fun patch() {
        if (cfg == null) {
            toast("Patch data failed to load, cannot continue")
            return
        }
        val inputsReady = when (mode) {
            InputMode.APK_PAIR -> baseUri != null && splitUri != null
            InputMode.XAPK -> xapkUri != null
        }
        if (!inputsReady) {
            toast("Complete the input selection first")
            return
        }
        val pkg = newPkg.trim()
        val renamed = pkg.isNotEmpty() && pkg != cfg.originalPackage
        if (renamed && !isValidPackageName(pkg)) {
            toast("Invalid package name, use e.g. " + cfg.originalPackage + ".patched")
            return
        }
        cfg.newPackage = if (renamed) pkg else null
        if (renamed) {
            logLine("Output package: $pkg (installs alongside the original)")
        }
        busy = true
        scope.launch {
            try {
                logLine("---")
                logLine("Patching (this may take a minute or two)...")
                val staging = File(context.cacheDir, "inputs").apply { mkdirs() }
                val prepared = withContext(Dispatchers.IO) {
                    when (mode) {
                        InputMode.APK_PAIR -> Pair(
                            copyUri(context, baseUri!!, File(staging, "base.apk")),
                            copyUri(context, splitUri!!, File(staging, "split.apk"))
                        )
                        InputMode.XAPK -> extractXapk(context, xapkUri!!, staging) { logLine(it) }
                    }
                }
                logLine("Base APK: " + prepared.first.name)
                if (prepared.second != null) logLine("Split APK: " + prepared.second!!.name)
                logLine("Patching binary + manifest...")
                val result = withContext(Dispatchers.IO) {
                    PatcherEngine.build(
                        prepared.first, prepared.second, cfg,
                        File(context.cacheDir, "patched-unsigned.apk")
                    )
                }
                result.log.forEach { logLine(it) }
                val outFile = File(context.filesDir, "INTTI-patched.apk")
                withContext(Dispatchers.IO) {
                    sign(context, File(context.cacheDir, "patched-unsigned.apk"), outFile)
                }
                logLine("Signed OK (" + outFile.length() / 1048576 + " MB)")
                logLine("Patched APK (temporary): " + outFile.absolutePath)
                patchedFile = outFile
                busy = false
                val msg = if (renamed) {
                    "Patched APK ready, install it to run it alongside the original INTTI!"
                } else {
                    "Patched APK ready, uninstall the original INTTI first, then install!"
                }
                toast(msg)
                installPrompt()
            } catch (e: Exception) {
                logLine("FAILED: " + e.message)
                toast("Patch failed: " + e.message)
                busy = false
            }
        }
    }

    fun installSaved() {
        installPrompt()
    }

    Scaffold { padding ->
        Column(
            Modifier
                .padding(padding)
                .fillMaxSize()
                .verticalScroll(scroll)
                .padding(16.dp)
        ) {
            Text("INTTI Patcher", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
            Text(
                cfgLabel,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                "No ads, no paywall, all units unlocked.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(12.dp))

            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                val opts = listOf(InputMode.APK_PAIR to "APK pair", InputMode.XAPK to "XAPK")
                opts.forEachIndexed { idx, (m, label) ->
                    SegmentedButton(
                        selected = mode == m,
                        onClick = { mode = m },
                        shape = SegmentedButtonDefaults.itemShape(idx, opts.size)
                    ) { Text(label) }
                }
            }
            Spacer(Modifier.height(12.dp))

            when (mode) {
                InputMode.APK_PAIR -> {
                    OutlinedButton(onClick = { basePicker.launch(arrayOf("*/*")) }, Modifier.fillMaxWidth()) {
                        Text(baseName ?: "Choose original base APK")
                    }
                    Spacer(Modifier.height(6.dp))
                    OutlinedButton(onClick = { splitPicker.launch(arrayOf("*/*")) }, Modifier.fillMaxWidth()) {
                        Text(splitName ?: "Choose config.arm64_v8a.apk")
                    }
                }
                InputMode.XAPK -> {
                    OutlinedButton(onClick = { xapkPicker.launch(arrayOf("*/*")) }, Modifier.fillMaxWidth()) {
                        Text(xapkName ?: "Choose the complete .xapk file")
                    }
                }
            }

            Spacer(Modifier.height(12.dp))

            OutlinedTextField(
                value = newPkg,
                onValueChange = { newPkg = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("New package name (optional)") },
                placeholder = { Text(cfg?.originalPackage + ".patched") },
                singleLine = true,
                supportingText = {
                    Text("Empty = keep the original package (you must uninstall the original app first). " +
                            "Enter a name like " + (cfg?.originalPackage ?: "com.OneGlitch.INTTI") +
                            ".patched to keep BOTH apps installed side by side.")
                }
            )

            Spacer(Modifier.height(12.dp))

            Button(
                onClick = { patch() },
                enabled = !busy && (when (mode) {
                    InputMode.APK_PAIR -> baseUri != null && splitUri != null
                    InputMode.XAPK -> xapkUri != null
                }),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(if (busy) "Working..." else "Patch and save APK")
            }

            if (busy) {
                Spacer(Modifier.height(8.dp))
                LinearProgressIndicator(Modifier.fillMaxWidth())
            }

            if (patchedFile != null) {
                Spacer(Modifier.height(8.dp))
                Button(onClick = { installSaved() }, Modifier.fillMaxWidth()) {
                    Text("Install the patched APK" +
                            (if (patchedFile!!.exists()) " (" + patchedFile!!.length() / 1048576 + " MB)" else ""))
                }
                Text(
                    "The patched APK is stored temporarily in this app's private storage",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 6.dp)
                )
            }

            Spacer(Modifier.height(16.dp))
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp)) {
                    Text("Log", style = MaterialTheme.typography.labelLarge)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        if (log.isEmpty()) "Waiting for input..." else log.joinToString("\n"),
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }
            Spacer(Modifier.height(24.dp))
        }
    }

    LaunchedEffect(log.size) {
        scroll.animateScrollTo(scroll.maxValue)
    }
}

//  Input preparation

private fun copyUri(context: Context, uri: Uri, dest: File): File {
    context.contentResolver.openInputStream(uri).use { input ->
        FileOutputStream(dest).use { output ->
            input!!.copyTo(output)
        }
    }
    return dest
}

private fun extractXapk(context: Context, uri: Uri, staging: File, log: (String) -> Unit): Pair<File, File?> {
    val xapkFile = File(staging, "input.xapk")
    copyUri(context, uri, xapkFile)

    val base = File(staging, "base.apk")
    val split = File(staging, "split.apk")
    var splitEntry: ZipEntry? = null
    ZipFile(xapkFile).use { zip ->
        val apks = zip.entries().asSequence()
            .filter { !it.isDirectory && it.name.endsWith(".apk", ignoreCase = true) }
            .toList()
        if (apks.isEmpty()) throw IllegalArgumentException("No .apk found inside the XAPK")

        splitEntry = apks.firstOrNull { it.name.contains("config.", ignoreCase = true) && it.name.contains("arm64", ignoreCase = true) }
        val baseEntry = apks.firstOrNull {
            it.name.substringAfterLast('/').equals("com.OneGlitch.INTTI.apk", ignoreCase = true)
        } ?: apks.firstOrNull { !it.name.substringAfterLast('/').startsWith("config.", ignoreCase = true) }
            ?: apks.first()

        log("XAPK contains: " + apks.joinToString(", ") { it.name })
        unzipEntry(zip, baseEntry, base)
        log("Extracted base: " + baseEntry.name)
        if (splitEntry != null) {
            unzipEntry(zip, splitEntry, split)
            log("Extracted split: " + splitEntry.name)
        } else {
            log("No arm64 split inside XAPK - using libs from the base APK")
        }
    }
    xapkFile.delete()
    return Pair(base, if (splitEntry != null) split else null)
}

private fun unzipEntry(zip: ZipFile, entry: ZipEntry, dest: File) {
    zip.getInputStream(entry).use { input ->
        FileOutputStream(dest).use { output -> input.copyTo(output) }
    }
}

private fun isValidPackageName(pkg: String): Boolean {
    if (pkg.length !in 3..150) return false
    val parts = pkg.split(".")
    if (parts.size < 2 || parts.any { it.isEmpty() }) return false
    return parts.all { seg ->
        seg[0].isLetter() && seg.all { c -> c.isLetterOrDigit() || c == '_' }
    }
}

//  Signing

private fun sign(context: Context, inFile: File, outFile: File) {
    val pw = "android123".toCharArray()
    val ks = KeyStore.getInstance("PKCS12")
    val alias = "release"
    ks.load(null, null)
    val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    val subject = X500Principal("CN=INTTI Patcher")
    val now = System.currentTimeMillis()
    val certHolder = JcaX509v3CertificateBuilder(
        subject,
        BigInteger.valueOf(now),
        Date(now - 1000L),
        Date(now + 100L * 365L * 24L * 3600L * 1000L),
        subject,
        kp.public
    ).build(JcaContentSignerBuilder("SHA256withRSA").build(kp.private))
    ks.setKeyEntry(alias, kp.private, pw, arrayOf<Certificate>(CertificateFactory.getInstance("X.509")
        .generateCertificate(ByteArrayInputStream(certHolder.encoded)) as X509Certificate))
    val entry = ks.getEntry(alias, KeyStore.PasswordProtection(pw)) as KeyStore.PrivateKeyEntry
    val cert = entry.certificate as X509Certificate
    val signer = ApkSigner.SignerConfig.Builder(
        alias, entry.privateKey, Collections.singletonList(cert)
    ).build()
    val b = ApkSigner.Builder(Collections.singletonList(signer))
    b.setInputApk(inFile)
    b.setOutputApk(outFile)
    b.setV1SigningEnabled(true)
    b.setV2SigningEnabled(true)
    b.setV3SigningEnabled(false)
    b.build().sign()
}