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
    private lateinit var layoutSplitMode: android.view.View
    private lateinit var btnModeExclude: MaterialButton
    private lateinit var btnModeInclude: MaterialButton
    private lateinit var textSplitHint: android.widget.TextView

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
        layoutSplitMode = view.findViewById(R.id.layout_split_mode)
        btnModeExclude = view.findViewById(R.id.btn_mode_exclude)
        btnModeInclude = view.findViewById(R.id.btn_mode_include)
        textSplitHint = view.findViewById(R.id.text_split_hint)
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

        // Split tunneling mode UI
        val splitOn = prefs.splitTunneling
        layoutSplitMode.visibility = if (splitOn) android.view.View.VISIBLE else android.view.View.GONE
        textSplitHint.visibility = if (splitOn) android.view.View.VISIBLE else android.view.View.GONE
        btnPickApps.isEnabled = splitOn
        updateModeButtons(prefs.splitMode)
        updatePickAppsButtonText(prefs)

        // Remote logging
        switchRemoteLogging.isChecked = prefs.remoteLogging
        updateLogStatusText(prefs.remoteLogging)
    }

    private fun updateModeButtons(mode: String) {
        // Store mode as tag on layout for saveSettings to read
        layoutSplitMode.tag = mode
        val ctx = requireContext()
        if (mode == "exclude") {
            // Exclude = FILLED (active, primary color)
            btnModeExclude.isSelected = true
            btnModeInclude.isSelected = false
            btnModeExclude.setBackgroundColor(com.google.android.material.color.MaterialColors.getColor(btnModeExclude, com.google.android.material.R.attr.colorPrimary, android.graphics.Color.BLUE))
            btnModeExclude.setTextColor(com.google.android.material.color.MaterialColors.getColor(btnModeExclude, com.google.android.material.R.attr.colorOnPrimary, android.graphics.Color.WHITE))
            btnModeExclude.strokeWidth = 0
            // Include = OUTLINED (inactive)
            btnModeInclude.setBackgroundColor(android.graphics.Color.TRANSPARENT)
            btnModeInclude.setTextColor(com.google.android.material.color.MaterialColors.getColor(btnModeInclude, com.google.android.material.R.attr.colorOnSurfaceVariant, android.graphics.Color.GRAY))
            btnModeInclude.strokeWidth = 2
        } else {
            // Exclude = OUTLINED (inactive)
            btnModeExclude.isSelected = false
            btnModeInclude.isSelected = true
            btnModeExclude.setBackgroundColor(android.graphics.Color.TRANSPARENT)
            btnModeExclude.setTextColor(com.google.android.material.color.MaterialColors.getColor(btnModeExclude, com.google.android.material.R.attr.colorOnSurfaceVariant, android.graphics.Color.GRAY))
            btnModeExclude.strokeWidth = 2
            // Include = FILLED (active, primary color)
            btnModeInclude.setBackgroundColor(com.google.android.material.color.MaterialColors.getColor(btnModeInclude, com.google.android.material.R.attr.colorPrimary, android.graphics.Color.BLUE))
            btnModeInclude.setTextColor(com.google.android.material.color.MaterialColors.getColor(btnModeInclude, com.google.android.material.R.attr.colorOnPrimary, android.graphics.Color.WHITE))
            btnModeInclude.strokeWidth = 0
        }
        // Add icon to active button for extra clarity
        btnModeExclude.setCompoundDrawablesRelativeWithIntrinsicBounds(
            if (mode == "exclude") android.R.drawable.ic_menu_close_clear_cancel else 0, 0, 0, 0)
        btnModeInclude.setCompoundDrawablesRelativeWithIntrinsicBounds(
            if (mode == "include") android.R.drawable.ic_menu_add else 0, 0, 0, 0)
    }

    private fun setupListeners() {
        switchAutoMtu.setOnCheckedChangeListener { _, isChecked ->
            editMtu.isEnabled = !isChecked
        }

        switchSplitTunneling.setOnCheckedChangeListener { _, isChecked ->
            btnPickApps.isEnabled = isChecked
            layoutSplitMode.visibility = if (isChecked) android.view.View.VISIBLE else android.view.View.GONE
            textSplitHint.visibility = if (isChecked) android.view.View.VISIBLE else android.view.View.GONE
            // Save immediately so VPN service reads correct value at connect time
            val app = requireActivity().application as TunnelyApp
            app.prefs.splitTunneling = isChecked
        }

        btnModeExclude.setOnClickListener {
            updateModeButtons("exclude")
            // Save immediately
            val app = requireActivity().application as TunnelyApp
            app.prefs.splitMode = "exclude"
        }

        btnModeInclude.setOnClickListener {
            updateModeButtons("include")
            // Save immediately
            val app = requireActivity().application as TunnelyApp
            app.prefs.splitMode = "include"
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
        // Only show apps that have a launcher icon (user-facing apps)
        val launcherPkgs = pm.queryIntentActivities(
            android.content.Intent(android.content.Intent.ACTION_MAIN).addCategory(android.content.Intent.CATEGORY_LAUNCHER),
            0
        ).map { it.activityInfo.packageName }.toSet()

        return pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            .filter { it.packageName != myPackage }
            .filter { it.packageName in launcherPkgs }  // only user-visible apps
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
                // Use commit() for synchronous write — apply() is async and VPN may connect before disk write
                prefs.splitApps = selected
                RemoteLogger.i("SettingsFragment", "Split apps saved via dialog: ${selected.size} apps = $selected")
                updatePickAppsButtonText(prefs)
                Toast.makeText(requireContext(), "${selected.size} apps selected for VPN", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Cancel", null)
            .setNeutralButton("Clear All") { _, _ ->
                prefs.splitApps = emptySet()
                RemoteLogger.i("SettingsFragment", "Split apps cleared via dialog")
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
        prefs.splitMode = (layoutSplitMode.tag as? String) ?: "exclude"
        prefs.allowedIps = allowedIps

        Toast.makeText(requireContext(), "Settings saved", Toast.LENGTH_SHORT).show()
    }
}
