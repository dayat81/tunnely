package com.tunnely.app.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import androidx.fragment.app.Fragment
import com.google.android.material.button.MaterialButton
import com.tunnely.app.R
import com.tunnely.app.TunnelyApp
import com.tunnely.app.vpn.VpnPreferences

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
    }

    private fun setupListeners() {
        switchAutoMtu.setOnCheckedChangeListener { _, isChecked ->
            editMtu.isEnabled = !isChecked
        }

        switchSplitTunneling.setOnCheckedChangeListener { _, isChecked ->
            btnPickApps.isEnabled = isChecked
        }

        btnSave.setOnClickListener {
            saveSettings()
        }

        btnPickApps.setOnClickListener {
            // TODO: Open app picker dialog
            Toast.makeText(requireContext(), "App picker coming soon", Toast.LENGTH_SHORT).show()
        }
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
