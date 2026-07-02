package com.tunnely.app.ui

import android.graphics.drawable.Drawable
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.tunnely.app.R

data class SplitTunnelApp(
    val packageName: String,
    val appName: String,
    val icon: Drawable?,
    var selected: Boolean,
)

class SplitTunnelAppAdapter(
    private val onToggle: (SplitTunnelApp) -> Unit,
) : RecyclerView.Adapter<SplitTunnelAppAdapter.ViewHolder>() {

    private var allApps = listOf<SplitTunnelApp>()
    private var filteredApps = listOf<SplitTunnelApp>()
    private var filterQuery = ""

    fun submitApps(apps: List<SplitTunnelApp>) {
        allApps = apps
        applyFilter()
    }

    fun setFilter(query: String) {
        filterQuery = query.lowercase()
        applyFilter()
    }

    private fun applyFilter() {
        filteredApps = if (filterQuery.isBlank()) {
            allApps
        } else {
            allApps.filter {
                it.appName.lowercase().contains(filterQuery) ||
                    it.packageName.lowercase().contains(filterQuery)
            }
        }
        notifyDataSetChanged()
    }

    fun getSelectedPackages(): Set<String> =
        allApps.filter { it.selected }.map { it.packageName }.toSet()

    fun setSelectedPackages(packages: Set<String>) {
        allApps.forEach { it.selected = it.packageName in packages }
        filteredApps.forEach { it.selected = it.packageName in packages }
        notifyDataSetChanged()
    }

    override fun getItemCount(): Int = filteredApps.size

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_split_tunnel_app, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        holder.bind(filteredApps[position])
    }

    inner class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val appIcon: ImageView = itemView.findViewById(R.id.appIcon)
        private val appName: TextView = itemView.findViewById(R.id.appName)
        private val appCheck: CheckBox = itemView.findViewById(R.id.appCheck)

        fun bind(app: SplitTunnelApp) {
            appIcon.setImageDrawable(app.icon)
            appName.text = app.appName
            appCheck.setOnCheckedChangeListener(null)
            appCheck.isChecked = app.selected
            appCheck.setOnCheckedChangeListener { _, isChecked ->
                app.selected = isChecked
                onToggle(app)
            }
            itemView.setOnClickListener {
                app.selected = !app.selected
                // Suppress listener to prevent double-toggle
                appCheck.setOnCheckedChangeListener(null)
                appCheck.isChecked = app.selected
                appCheck.setOnCheckedChangeListener { _, isChecked ->
                    app.selected = isChecked
                    onToggle(app)
                }
                onToggle(app)
            }
        }
    }
}
