import networkx as nx
import plotly.graph_objects as go
import numpy as np
#create the network plot
def create_network_plot(scan_data):
    G = nx.Graph()
    G.add_node("Scanner")
    
    # Add nodes and edges
    for host in scan_data:
        ip = host[0]
        latency = float(host[1].strip("()s")) * 1000
        G.add_node(ip)
        G.add_edge("Scanner", ip, weight=latency)

    pos = nx.spring_layout(G, k=0.5, iterations=50)

    # Create edge traces
    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.append(x0)
        edge_x.append(x1)
        edge_x.append(None)
        edge_y.append(y0)
        edge_y.append(y1)
        edge_y.append(None)

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        mode='lines')

    # Create node traces
    node_x = []
    node_y = []
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)

    # Prepare node text and hover information
    node_text = []
    hover_text = []
    for node in G.nodes():
        if node == "Scanner":
            node_text.append("Scanner")
            hover_text.append("Scanner")
        else:
            latency = G[node]["Scanner"]["weight"]
            node_text.append(node)  # Only IP for display
            hover_text.append(f"{node}<br>Latency: {latency:.2f}ms")

    #create the node trace
    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        text=node_text,
        hovertext=hover_text,
        hoverinfo='text',
        textposition="bottom center",
        marker=dict(
            color=['#1f77b4' if node == "Scanner" else '#2ca02c' for node in G.nodes()],
            size=15,
            line_width=2,
            showscale=False
        ))

    # Create the figure
    fig = go.Figure(
        data=[edge_trace, node_trace],
        layout=go.Layout(
            title='<br>Network Scan Visualization',
            titlefont=dict(size=16),
            showlegend=False,
            hovermode='closest',
            margin=dict(b=20,l=5,r=5,t=40),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            plot_bgcolor='white'
        )
    )
    
    return fig.to_html(full_html=False)

#create the tcp/udp plot
def create_tcp_udp_plot(scan_data):
    plots = {}
    
    # Group data by IP address
    ip_data = {}
    for scan in scan_data:
        ip = scan[0]
        if ip not in ip_data:
            ip_data[ip] = []
        ip_data[ip].append({
            'port': scan[1],
            'state': scan[2],
            'service': scan[3],
            'scan_type': scan[4]
        })

    # Create separate plot for each IP
    for ip, ports_info in ip_data.items():
        G = nx.Graph()
        G.add_node(ip)  # Center node (IP)
        
        # Add port nodes
        for port in ports_info:
            port_num = port['port'].split('/')[0]
            G.add_node(port_num)
            G.add_edge(ip, port_num)

        # Use same layout style as ICMP but with IP in center
        pos = nx.spring_layout(G, k=0.5, iterations=50)
        
        # Move IP to center
        center = np.array([0, 0])
        pos[ip] = center

        # Create edge traces
        edge_x = []
        edge_y = []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=0.5, color='#888'),
            hoverinfo='none',
            mode='lines')

        # Create node traces
        node_x = []
        node_y = []
        node_text = []
        hover_text = []
        node_colors = []

        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            
            if node == ip:
                node_text.append(ip)
                hover_text.append(f"<b>{ip}</b>")
                node_colors.append('#1f77b4')  
            else:
                port_info = next(p for p in ports_info if p['port'].split('/')[0] == node)
                node_text.append(node)  
                hover_info = (
                    f"Port: {port_info['port']}<br>"
                    f"State: {port_info['state']}<br>"
                    f"Service: {port_info['service']}<br>"
                    f"Type: {port_info['scan_type']}"
                )
                hover_text.append(hover_info)
                if port_info['state'] == 'open':
                    node_colors.append('green')  
                elif port_info['state'] == 'closed':
                    node_colors.append('red')  
                else:
                    node_colors.append('orange')  

        #create the node trace
        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            text=node_text,
            hovertext=hover_text,
            hoverinfo='text',
            textposition="bottom center",
            marker=dict(
                color=node_colors,
                size=15,
                line_width=2
            ))

        #create the figure
        fig = go.Figure(
            data=[edge_trace, node_trace],
            layout=go.Layout(
                showlegend=False,
                hovermode='closest',
                margin=dict(b=20,l=5,r=5,t=40),
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                plot_bgcolor='white'
            )
        )
        
        plots[ip] = fig.to_html(full_html=False)
    
    return plots


#Source ----------------- https://plotly.com/python/network-graphs/     --------------
 

