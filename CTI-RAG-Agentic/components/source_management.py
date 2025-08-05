"""
Source Management Component for Streamlit UI

Provides interface for managing CTI data sources:
- View all sources
- Add new sources
- Enable/disable sources
- Update source configurations
- Remove sources
"""

import streamlit as st
import pandas as pd
from typing import Dict, Any, List
from services.data_source_manager import DataSourceManager, DataSource

def render_source_management():
    """Render the source management interface"""
    st.header("🔧 Data Source Management")
    
    # Initialize data source manager
    data_source_manager = DataSourceManager()
    
    # Get source statistics
    source_stats = data_source_manager.get_source_stats()
    
    # Display statistics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Sources", source_stats.get("total_sources", 0))
    with col2:
        st.metric("Enabled Sources", source_stats.get("enabled_sources", 0))
    with col3:
        st.metric("Disabled Sources", source_stats.get("disabled_sources", 0))
    with col4:
        source_types = source_stats.get("source_types", {})
        st.metric("RSS Sources", source_types.get("rss", 0))
    
    # Tabs for different management functions
    tab1, tab2, tab3, tab4 = st.tabs(["📋 View Sources", "➕ Add Source", "⚙️ Edit Sources", "🗑️ Remove Sources"])
    
    with tab1:
        render_view_sources(data_source_manager)
    
    with tab2:
        render_add_source(data_source_manager)
    
    with tab3:
        render_edit_sources(data_source_manager)
    
    with tab4:
        render_remove_sources(data_source_manager)

def render_view_sources(data_source_manager: DataSourceManager):
    """Render the view sources tab"""
    st.subheader("📋 Current Data Sources")
    
    sources = data_source_manager.get_sources(enabled_only=False)
    
    if not sources:
        st.warning("No data sources configured.")
        return
    
    # Create DataFrame for display
    source_data = []
    for source in sources:
        source_data.append({
            "Label": source.label,
            "Feed URL": source.feed_url,
            "Type": source.source_type,
            "Status": "✅ Enabled" if source.enabled else "❌ Disabled",
            "Max Posts": source.max_posts,
            "Priority": source.priority,
            "Last Updated": source.last_updated.strftime("%Y-%m-%d %H:%M") if source.last_updated else "Never"
        })
    
    df = pd.DataFrame(source_data)
    
    # Display with styling
    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True
    )
    
    # Export functionality
    if st.button("📤 Export Sources"):
        export_file = "data_sources_export.tsv"
        if data_source_manager.export_sources(export_file):
            with open(export_file, "r") as f:
                st.download_button(
                    label="📥 Download Sources File",
                    data=f.read(),
                    file_name=export_file,
                    mime="text/tab-separated-values"
                )
        else:
            st.error("Failed to export sources")

def render_add_source(data_source_manager: DataSourceManager):
    """Render the add source tab"""
    st.subheader("➕ Add New Data Source")
    
    with st.form("add_source_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            label = st.text_input("Source Label", placeholder="e.g., New Vendor")
            feed_url = st.text_input("Feed URL", placeholder="https://example.com/feed/")
            source_type = st.selectbox(
                "Source Type",
                ["rss", "api", "csv", "web"],
                help="RSS for blog feeds, API for REST endpoints, CSV for data files"
            )
        
        with col2:
            enabled = st.checkbox("Enabled", value=True)
            max_posts = st.number_input("Max Posts", min_value=1, max_value=1000, value=50)
            priority = st.number_input("Priority", min_value=1, max_value=10, value=1)
        
        submitted = st.form_submit_button("Add Source")
        
        if submitted:
            if not label or not feed_url:
                st.error("Please provide both label and feed URL")
                return
            
            # Check if source already exists
            existing_source = data_source_manager.get_source(label)
            if existing_source:
                st.error(f"Source '{label}' already exists")
                return
            
            # Create new source
            new_source = DataSource(
                label=label,
                feed_url=feed_url,
                source_type=source_type,
                enabled=enabled,
                max_posts=max_posts,
                priority=priority
            )
            
            if data_source_manager.add_source(new_source):
                st.success(f"✅ Successfully added source: {label}")
                st.rerun()
            else:
                st.error(f"❌ Failed to add source: {label}")

def render_edit_sources(data_source_manager: DataSourceManager):
    """Render the edit sources tab"""
    st.subheader("⚙️ Edit Data Sources")
    
    sources = data_source_manager.get_sources(enabled_only=False)
    
    if not sources:
        st.warning("No data sources to edit.")
        return
    
    # Create a form for each source
    for source in sources:
        with st.expander(f"{source.label} ({source.source_type})"):
            with st.form(f"edit_source_{source.label}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    source_id = f"{source.label}_{id(source)}"
                    new_label = st.text_input("Label", value=source.label, key=f"label_{source_id}")
                    new_feed_url = st.text_input("Feed URL", value=source.feed_url, key=f"url_{source_id}")
                    new_source_type = st.selectbox(
                        "Source Type",
                        ["rss", "api", "csv", "web"],
                        index=["rss", "api", "csv", "web"].index(source.source_type),
                        key=f"type_{source_id}"
                    )
                
                with col2:
                    new_enabled = st.checkbox("Enabled", value=source.enabled, key=f"enabled_{source_id}")
                    new_max_posts = st.number_input("Max Posts", min_value=1, max_value=1000, value=source.max_posts, key=f"max_{source_id}")
                    new_priority = st.number_input("Priority", min_value=1, max_value=10, value=source.priority, key=f"priority_{source_id}")
                
                col1, col2 = st.columns(2)
                with col1:
                    if st.form_submit_button("Update"):
                        updates = {}
                        if new_label != source.label:
                            updates["label"] = new_label
                        if new_feed_url != source.feed_url:
                            updates["feed_url"] = new_feed_url
                        if new_source_type != source.source_type:
                            updates["source_type"] = new_source_type
                        if new_enabled != source.enabled:
                            updates["enabled"] = new_enabled
                        if new_max_posts != source.max_posts:
                            updates["max_posts"] = new_max_posts
                        if new_priority != source.priority:
                            updates["priority"] = new_priority
                        
                        if updates:
                            if data_source_manager.update_source(source.label, **updates):
                                st.success(f"✅ Updated {source.label}")
                                st.rerun()
                            else:
                                st.error(f"❌ Failed to update {source.label}")
                        else:
                            st.info("No changes made")
                
                with col2:
                    if st.form_submit_button("Toggle Status"):
                        new_status = not source.enabled
                        if data_source_manager.update_source(source.label, enabled=new_status):
                            status_text = "enabled" if new_status else "disabled"
                            st.success(f"✅ {source.label} {status_text}")
                            st.rerun()
                        else:
                            st.error(f"❌ Failed to update {source.label}")

def render_remove_sources(data_source_manager: DataSourceManager):
    """Render the remove sources tab"""
    st.subheader("🗑️ Remove Data Sources")
    
    sources = data_source_manager.get_sources(enabled_only=False)
    
    if not sources:
        st.warning("No data sources to remove.")
        return
    
    st.warning("⚠️ Removing a source will permanently delete it from the configuration.")
    
    # Create a list of sources to remove
    source_labels = [source.label for source in sources]
    selected_sources = st.multiselect(
        "Select sources to remove:",
        source_labels,
        help="Select one or more sources to remove"
    )
    
    if selected_sources:
        if st.button("🗑️ Remove Selected Sources", type="primary"):
            removed_count = 0
            failed_count = 0
            
            for source_label in selected_sources:
                if data_source_manager.remove_source(source_label):
                    removed_count += 1
                else:
                    failed_count += 1
            
            if removed_count > 0:
                st.success(f"✅ Successfully removed {removed_count} source(s)")
            if failed_count > 0:
                st.error(f"❌ Failed to remove {failed_count} source(s)")
            
            if removed_count > 0:
                st.rerun()

def render_source_import():
    """Render source import functionality"""
    st.subheader("📥 Import Sources")
    
    uploaded_file = st.file_uploader(
        "Upload TSV file with sources",
        type=['tsv'],
        help="Upload a TSV file with columns: Label, Feed URL, Source Type, Enabled, Max Posts, Priority"
    )
    
    if uploaded_file is not None:
        try:
            # Read the uploaded file
            content = uploaded_file.read().decode('utf-8')
            
            # Save to temporary file
            temp_file = "temp_sources.tsv"
            with open(temp_file, 'w') as f:
                f.write(content)
            
            # Import sources
            data_source_manager = DataSourceManager()
            if data_source_manager.import_sources(temp_file):
                st.success("✅ Successfully imported sources")
                st.rerun()
            else:
                st.error("❌ Failed to import sources")
                
        except Exception as e:
            st.error(f"❌ Error processing file: {e}")

def render_source_management_sidebar():
    """Render source management in sidebar"""
    st.sidebar.header("🔧 Source Management")
    
    data_source_manager = DataSourceManager()
    source_stats = data_source_manager.get_source_stats()
    
    st.sidebar.metric("Total Sources", source_stats.get("total_sources", 0))
    st.sidebar.metric("Enabled", source_stats.get("enabled_sources", 0))
    
    if st.sidebar.button("🔄 Refresh Sources"):
        st.rerun()
    
    # Quick actions
    st.sidebar.subheader("Quick Actions")
    
    if st.sidebar.button("📤 Export Sources"):
        export_file = "data_sources_export.tsv"
        if data_source_manager.export_sources(export_file):
            with open(export_file, "r") as f:
                st.sidebar.download_button(
                    label="📥 Download",
                    data=f.read(),
                    file_name=export_file,
                    mime="text/tab-separated-values"
                )
    
    # Import functionality
    st.sidebar.subheader("Import Sources")
    uploaded_file = st.sidebar.file_uploader(
        "Upload TSV",
        type=['tsv'],
        key="sidebar_upload"
    )
    
    if uploaded_file is not None:
        try:
            content = uploaded_file.read().decode('utf-8')
            temp_file = "temp_sources_sidebar.tsv"
            with open(temp_file, 'w') as f:
                f.write(content)
            
            if data_source_manager.import_sources(temp_file):
                st.sidebar.success("✅ Imported")
                st.rerun()
            else:
                st.sidebar.error("❌ Import failed")
                
        except Exception as e:
            st.sidebar.error(f"❌ Error: {e}") 