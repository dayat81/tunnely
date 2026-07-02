package com.tunnely.app.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.tunnely.app.R
import com.tunnely.app.rtt.AppRttTarget

/**
 * Adapter for app selection in RTT test picker dialog.
 * Shows installed apps with known server targets.
 */
class AppRttAdapter(
    private val onToggle: (AppRttTarget) -> Unit = {}
) : RecyclerView.Adapter<AppRttAdapter.ViewHolder>() {

    private var apps = listOf<AppRttTarget>()
    private var selectedPackages = mutableSetOf<String>()

    fun submitApps(newApps: List<AppRttTarget>) {
        apps = newApps
        notifyDataSetChanged()
    }

    fun setSelectedPackages(packages: Set<String>) {
        selectedPackages = packages.toMutableSet()
        notifyDataSetChanged()
    }

    fun getSelectedPackages(): Set<String> = selectedPackages.toSet()

    fun getSelectedTargets(): List<AppRttTarget> {
        return apps.filter { it.packageName in selectedPackages }
    }

    override fun getItemCount() = apps.size

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_app_rtt, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val app = apps[position]
        val isSelected = app.packageName in selectedPackages

        holder.bind(app, isSelected)

        // Toggle on row click
        holder.itemView.setOnClickListener {
            toggleSelection(app)
        }

        // Toggle on checkbox click
        holder.checkBox.setOnClickListener {
            toggleSelection(app)
        }
    }

    private fun toggleSelection(app: AppRttTarget) {
        if (app.packageName in selectedPackages) {
            selectedPackages.remove(app.packageName)
        } else {
            selectedPackages.add(app.packageName)
        }
        onToggle(app)
        notifyDataSetChanged()
    }

    class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val checkBox: CheckBox = itemView.findViewById(R.id.app_checkbox)
        private val icon: ImageView = itemView.findViewById(R.id.app_icon)
        private val name: TextView = itemView.findViewById(R.id.app_name)
        private val host: TextView = itemView.findViewById(R.id.app_host)

        fun bind(app: AppRttTarget, isSelected: Boolean) {
            checkBox.isChecked = isSelected
            icon.setImageDrawable(app.icon)
            name.text = app.appName
            host.text = "${app.target.name} → ${app.target.host}"
        }
    }
}
