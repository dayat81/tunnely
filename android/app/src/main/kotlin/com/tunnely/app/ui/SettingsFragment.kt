package com.tunnely.app.ui

import android.content.pm.PackageManager
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.Switch
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.button.MaterialButton
import com.tunnely.app.R
import com.tunnely.app.TunnelyApp
import com.tunnely.app.vpn.RemoteLogger
import com.tunnely.app.vpn.VpnPreferences
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class SettingsFragment : Fragment() {

    private lateinit var editServerAddress: EditText
    private lateinit var editServerPort: EditText
    private lateinit var editDns: EditText
    private lateinit var editMtu: EditText
    private lateinit var switchAutoMtu: Switch
    private lateinit var switchSplitTunneling: Switch
    private lateinit var editAllowedIps: EditText
    private lateinit var btnSave: MaterialButton
    private lateinit var btnPickApps: MaterialButton
    private lateinit var switchRemoteLogging: Switch
    private lateinit var textLogStatus: android.widget.TextView

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.fragment_settings, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        initViews(view)
        loadSettings()
        setupListeners()
    }

    private fun initViews(view: View) {
        editServerAddress = view.findViewById(R.id.edit_server_address)
        editServerPort = view.findViewById(R.id.edit_server_port)
        editDns = view.findViewById(R.id.edit_dns)
        editMtu = view.findViewById(R.id.edit_mtu)
        switchAutoMtu = view.findViewById(R.id.switch_auto_mtu)
        switchSplitTunneling = view.findViewById(R.id.switch_split_tunneling)
        editAllowedIps = view.findViewById(R.id.edit_allowed_ips)
        btnSave = view.findViewById(R.id.btn_save)
        btnPickApps = view.findViewById(R.id.btn_pick_apps)
        switchRemoteLogging = view.findViewById(R.id.switch_remote_logging)
        textLogStatus = view.findViewById(R.id.text_log_status)
    }

    private fun loadSettings() {
        val app = requireActivity().application as TunnelyApp
        val prefs = app.prefs

        editServerAddress.setText(prefs.serverAddress)
        editServerPort.setText(prefs.serverPort.toString())
        editDns.setText(prefs.dnsServers)
        editMtu.setText(prefs.mtu.toString())
        switchAutoMtu.isChecked = prefs.autoMtu
        switchSplitTunneling.isChecked = prefs.splitTunneling
        editAllowedIps.setText(prefs.allowedIps)

        // MTU edit should be disabled when auto is on
        editMtu.isEnabled = !prefs.autoMtu

        // App picker should be disabled when split tunneling is off
        btnPickApps.isEnabled = prefs.splitTunneling
        updatePickAppsButtonText(prefs)

        // Remote logging
        switchRemoteLogging.isChecked = prefs.remoteLogging
        updateLogStatusText(prefs.remoteLogging)
    }

    private fun setupListeners() {
        switchAutoMtu.setOnCheckedChangeListener { _, isChecked ->
            editMtu.isEnabled = !isChecked
        }

        switchSplitTunneling.setOnCheckedChangeListener { _, isChecked ->
            btnPickApps.isEnabled = isChecked
        }

        switchRemoteLogging.setOnCheckedChangeListener { _, isChecked ->
            RemoteLogger.setEnabled(isChecked)
            updateLogStatusText(isChecked)
            Toast.makeText(requireContext(),
                if (isChecked) "Remote logging ON — logs pushed to server every 10s"
                else "Remote logging OFF",
                Toast.LENGTH_SHORT
            ).show()
        }

        btnSave.setOnClickListener {
            saveSettings()
        }

        btnPickApps.setOnClickListener {
            showAppPickerDialog()
        }
    }

    private fun updatePickAppsButtonText(prefs: VpnPreferences) {
        val count = prefs.splitApps.size
        btnPickApps.text = if (count > 0) {
            "Select Apps ($count selected)"
        } else {
            "Select Apps"
        }
    }

    private fun updateLogStatusText(enabled: Boolean) {
        textLogStatus.text = if (enabled) {
            "Status: ✅ Active — pushing to https://${(requireActivity().application as TunnelyApp).prefs.serverAddress}/api/vpn/logs"
        } else {
            "Status: Disabled"
        }
    }

    private fun showAppPickerDialog() {
        val app = requireActivity().application as TunnelyApp
        val prefs = app.prefs

        // Prevent button spam
        btnPickApps.isEnabled = false

        // Show loading dialog immediately (appears instantly, no freeze)
        val progressBar = ProgressBar(requireContext()).apply {
            setPadding(0, 48, 0, 48)
        }
        val loadingDialog = AlertDialog.Builder(requireContext(), R.style.Theme_Tunnely_Dialog)
            .setTitle("Loading apps…")
            .setView(progressBar)
            .setCancelable(true)
            .create()

        loadingDialog.setOnCancelListener {
            btnPickApps.isEnabled = switchSplitTunneling.isChecked
        }
        loadingDialog.show()

        // Capture context for IO thread (requireContext() is UI-only)
        val ctx = requireContext()
        val pm = ctx.packageManager
        val myPackage = ctx.packageName

        // Load apps off the UI thread — no freeze, no focus leak
        viewLifecycleOwner.lifecycleScope.launch {
            val installedApps = withContext(Dispatchers.IO) {
                loadInstalledApps(pm, myPackage, prefs)
            }

            // Fragment may have been detached during loading
            if (!isAdded || !loadingDialog.isShowing) {
                btnPickApps.isEnabled = switchSplitTunneling.isChecked
                return@launch
            }

            loadingDialog.dismiss()
            showAppPickerDialogWithData(installedApps, prefs)
        }
    }

    private fun loadInstalledApps(
        pm: PackageManager,
        myPackage: String,
        prefs: VpnPreferences
    ): List<SplitTunnelApp> {
        return pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            .filter { it.packageName != myPackage }
            .filter { pkg ->
                val perms = pkg.requestedPermissions
                perms == null || perms.contains(android.Manifest.permission.INTERNET)
            }
            .mapNotNull { pkg ->
                val appInfo = pkg.applicationInfo ?: return@mapNotNull null
                SplitTunnelApp(
                    packageName = pkg.packageName,
                    appName = pm.getApplicationLabel(appInfo).toString(),
                    icon = pm.getApplicationIcon(appInfo),
                    selected = pkg.packageName in prefs.splitApps
                )
            }
            .sortedBy { it.appName.lowercase() }
    }

    private fun showAppPickerDialogWithData(
        installedApps: List<SplitTunnelApp>,
        prefs: VpnPreferences
    ) {
        val adapter = SplitTunnelAppAdapter { /* toggle handled internally */ }
        adapter.submitApps(installedApps)
        adapter.setSelectedPackages(prefs.splitApps)

        val searchEdit = EditText(requireContext()).apply {
            hint = "Search apps…"
            setPadding(48, 24, 48, 24)
            setTextColor(resources.getColor(R.color.text_primary, null))
            setHintTextColor(resources.getColor(R.color.text_secondary, null))
            // Don't auto-grab focus — prevents focus leak
            isFocusableInTouchMode = false
        }

        val recyclerView = RecyclerView(requireContext()).apply {
            layoutManager = LinearLayoutManager(requireContext())
            this.adapter = adapter
            setPadding(0, 8, 0, 8)
        }

        val container = android.widget.LinearLayout(requireContext()).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            addView(searchEdit, android.widget.LinearLayout.LayoutParams(
                android.widget.LinearLayout.LayoutParams.MATCH_PARENT,
                android.widget.LinearLayout.LayoutParams.WRAP_CONTENT
            ))
            addView(recyclerView, android.widget.LinearLayout.LayoutParams(
                android.widget.LinearLayout.LayoutParams.MATCH_PARENT,
                0, 1f
            ))
        }

        val dialog = AlertDialog.Builder(requireContext(), R.style.Theme_Tunnely_Dialog)
            .setTitle("Split Tunneling — Select Apps")
            .setView(container)
            .setPositiveButton("Save") { _, _ ->
                val selected = adapter.getSelectedPackages()
                prefs.splitApps = selected
                updatePickAppsButtonText(prefs)
                Toast.makeText(requireContext(), "${selected.size} apps selected for VPN", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Cancel", null)
            .setNeutralButton("Clear All") { _, _ ->
                prefs.splitApps = emptySet()
                updatePickAppsButtonText(prefs)
            }
            .create()

        // Prevent keyboard from auto-opening (another focus leak source)
        dialog.window?.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_HIDDEN)
        dialog.show()

        // Re-enable button + update count when dialog is dismissed (Save/Cancel/Clear)
        dialog.setOnDismissListener {
            btnPickApps.isEnabled = switchSplitTunneling.isChecked
            updatePickAppsButtonText(prefs)
        }

        // Now that dialog owns the window, enable search field focus safely
        searchEdit.post {
            searchEdit.isFocusableInTouchMode = true
        }

        // Search filtering
        searchEdit.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) {
                adapter.setFilter(s?.toString() ?: "")
            }
        })
    }

    private fun saveSettings() {
        val app = requireActivity().application as TunnelyApp
        val prefs = app.prefs

        // Validate inputs
        val serverAddress = editServerAddress.text.toString().trim()
        val serverPortStr = editServerPort.text.toString().trim()
        val dns = editDns.text.toString().trim()
        val mtuStr = editMtu.text.toString().trim()
        val allowedIps = editAllowedIps.text.toString().trim()

        if (serverAddress.isEmpty()) {
            editServerAddress.error = "Server address required"
            return
        }

        val serverPort = serverPortStr.toIntOrNull()
        if (serverPort == null || serverPort !in 1..65535) {
            editServerPort.error = "Invalid port"
            return
        }

        val mtu = mtuStr.toIntOrNull()
        if (mtu == null || mtu !in 576..1500) {
            editMtu.error = "MTU must be 576-1500"
            return
        }

        if (allowedIps.isEmpty()) {
            editAllowedIps.error = "Allowed IPs required"
            return
        }

        // Save all settings
        prefs.serverAddress = serverAddress
        prefs.serverPort = serverPort
        prefs.dnsServers = dns
        prefs.mtu = mtu
        prefs.autoMtu = switchAutoMtu.isChecked
        prefs.splitTunneling = switchSplitTunneling.isChecked
        prefs.allowedIps = allowedIps

        Toast.makeText(requireContext(), "Settings saved", Toast.LENGTH_SHORT).show()
    }
}
