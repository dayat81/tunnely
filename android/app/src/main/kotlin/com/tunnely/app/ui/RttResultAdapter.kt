package com.tunnely.app.ui

import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.tunnely.app.R
import com.tunnely.app.rtt.RttResult

class RttResultAdapter : RecyclerView.Adapter<RttResultAdapter.ViewHolder>() {

    private var results = listOf<RttResult>()

    fun submitResults(newResults: List<RttResult>) {
        results = newResults
        notifyDataSetChanged()
    }

    override fun getItemCount() = results.size

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_rtt_result, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        holder.bind(results[position])
    }

    class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val ratingDot: View = itemView.findViewById(R.id.rating_dot)
        private val appName: TextView = itemView.findViewById(R.id.app_name)
        private val directRtt: TextView = itemView.findViewById(R.id.direct_rtt)
        private val vpnRtt: TextView = itemView.findViewById(R.id.vpn_rtt)

        fun bind(result: RttResult) {
            appName.text = result.target.name

            // Rating dot color
            val dotColor = when (result.rating) {
                RttResult.Rating.GREEN -> Color.parseColor("#4CAF50")
                RttResult.Rating.YELLOW -> Color.parseColor("#FFC107")
                RttResult.Rating.RED -> Color.parseColor("#F44336")
                RttResult.Rating.TIMEOUT -> Color.parseColor("#9E9E9E")
            }
            val dot = GradientDrawable()
            dot.shape = GradientDrawable.OVAL
            dot.setColor(dotColor)
            ratingDot.background = dot

            // Direct RTT
            if (result.directTotalMs >= 0) {
                directRtt.text = "${result.directTotalMs}ms"
                directRtt.setTextColor(Color.parseColor("#4CAF50"))
            } else {
                directRtt.text = "timeout"
                directRtt.setTextColor(Color.parseColor("#9E9E9E"))
            }

            // VPN RTT
            if (result.vpnTotalMs >= 0) {
                vpnRtt.text = "${result.vpnTotalMs}ms"
                vpnRtt.setTextColor(Color.parseColor("#2196F3"))
            } else {
                vpnRtt.text = "timeout"
                vpnRtt.setTextColor(Color.parseColor("#9E9E9E"))
            }
        }
    }
}
