package com.tunnely.app.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.tunnely.app.R
import com.tunnely.app.vpn.FlowEntry

class FlowAdapter : ListAdapter<FlowEntry, FlowAdapter.FlowViewHolder>(FlowDiffCallback()) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): FlowViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_flow, parent, false)
        return FlowViewHolder(view)
    }

    override fun onBindViewHolder(holder: FlowViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    inner class FlowViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val serverText: TextView = itemView.findViewById(R.id.flow_server)
        private val protocolBadge: TextView = itemView.findViewById(R.id.flow_protocol)
        private val uplinkText: TextView = itemView.findViewById(R.id.flow_uplink)
        private val downlinkText: TextView = itemView.findViewById(R.id.flow_downlink)

        fun bind(entry: FlowEntry) {
            serverText.text = entry.displayServer
            protocolBadge.text = entry.protocol

            // Set protocol badge color
            val badgeColor = if (entry.protocol.uppercase().startsWith("TCP")) {
                itemView.context.getColor(R.color.protocol_tcp)
            } else {
                itemView.context.getColor(R.color.protocol_udp)
            }
            protocolBadge.background.setTint(badgeColor)

            if (entry.uplinkBytes > 0 || entry.downlinkBytes > 0) {
                uplinkText.text = "↑ ${entry.displayUplink}"
                downlinkText.text = "↓ ${entry.displayDownlink}"
                uplinkText.visibility = View.VISIBLE
                downlinkText.visibility = View.VISIBLE
            } else {
                // Local flows without byte counters — show as active connection
                uplinkText.text = "● active"
                uplinkText.setTextColor(itemView.context.getColor(R.color.accent))
                downlinkText.visibility = View.GONE
            }
        }
    }

    class FlowDiffCallback : DiffUtil.ItemCallback<FlowEntry>() {
        override fun areItemsTheSame(oldItem: FlowEntry, newItem: FlowEntry): Boolean {
            return oldItem.server == newItem.server &&
                   oldItem.port == newItem.port &&
                   oldItem.protocol == newItem.protocol
        }

        override fun areContentsTheSame(oldItem: FlowEntry, newItem: FlowEntry): Boolean {
            return oldItem == newItem
        }
    }
}
