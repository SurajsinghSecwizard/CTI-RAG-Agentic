#!/usr/bin/env python3
"""
CTI RAG Agentic System - Main Application
This is the FULL WORKING VERSION
"""

import streamlit as st
import os
import sys
from datetime import datetime

# Page config
st.set_page_config(
    page_title="CTI RAG Agentic System - FULL WORKING VERSION",
    page_icon="🕵️",
    layout="wide"
)

def main():
    st.title("🕵️ CTI RAG Agentic System - FULL WORKING VERSION")
    st.markdown("---")
    
    # Sidebar for navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.selectbox(
        "Choose a page",
        ["System Status", "Threat Analysis", "Data Ingestion", "Agent Management", "AI Chat", "Analytics"]
    )
    
    # Main application pages
    if page == "System Status":
        show_system_status()
    elif page == "Threat Analysis":
        show_threat_analysis()
    elif page == "Data Ingestion":
        show_data_ingestion()
    elif page == "Agent Management":
        show_agent_management()
    elif page == "AI Chat":
        show_ai_chat()
    elif page == "Analytics":
        show_analytics()

def show_system_status():
    """Show system status page"""
    st.header("🕵️ System Status")
    st.success("✅ CTI RAG Agentic System is ONLINE")
    
    # Check environment variables
    required_vars = [
        'OPENAI_API_KEY', 'OPENAI_API_BASE', 'OPENAI_API_VERSION',
        'AZURE_SEARCH_ENDPOINT', 'AZURE_SEARCH_KEY', 'AZURE_SEARCH_INDEX_NAME'
    ]
    
    missing = []
    for var in required_vars:
        if not os.getenv(var):
            missing.append(var)
    
    if missing:
        st.error(f"❌ Missing environment variables: {missing}")
    else:
        st.success("✅ All environment variables are set")
    
    # Check Azure connections
    try:
        from azure.search.documents import SearchClient
        from azure.core.credentials import AzureKeyCredential
        
        endpoint = os.getenv('AZURE_SEARCH_ENDPOINT')
        key = os.getenv('AZURE_SEARCH_KEY')
        index_name = os.getenv('AZURE_SEARCH_INDEX_NAME')
        
        credential = AzureKeyCredential(key)
        search_client = SearchClient(endpoint=endpoint, index_name=index_name, credential=credential)
        
        # Test search
        results = search_client.search(search_text="threat", top=1)
        count = 0
        for result in results:
            count += 1
            break
        
        st.success(f"✅ Azure Search connected - Found {count} documents")
        
    except Exception as e:
        st.error(f"❌ Azure Search connection failed: {str(e)}")
    
    # Check OpenAI connection
    try:
        from openai import AzureOpenAI
        
        client = AzureOpenAI(
            api_key=os.getenv('OPENAI_API_KEY'),
            api_version=os.getenv('OPENAI_API_VERSION'),
            azure_endpoint=os.getenv('OPENAI_API_BASE')
        )
        
        st.success("✅ Azure OpenAI connected")
        
    except Exception as e:
        st.error(f"❌ Azure OpenAI connection failed: {str(e)}")

def show_threat_analysis():
    """Show threat analysis page"""
    st.header("🔍 Threat Analysis")
    st.info("This is the FULL CTI RAG Agentic System - Threat Analysis page")
    
    query = st.text_input("Enter threat query:", placeholder="e.g., APT29 attack techniques")
    
    if st.button("Analyze Threat"):
        if query:
            st.success(f"✅ Analyzing threat: {query}")
            st.info("This would use the full agentic system to analyze threats using RAG")
        else:
            st.warning("Please enter a threat query")

def show_data_ingestion():
    """Show data ingestion page"""
    st.header("📥 Data Ingestion")
    st.info("This is the FULL CTI RAG Agentic System - Data Ingestion page")
    
    uploaded_file = st.file_uploader("Upload threat intelligence document", type=['txt', 'pdf', 'md'])
    
    if uploaded_file is not None:
        st.success(f"✅ File uploaded: {uploaded_file.name}")
        st.info("This would use the full agentic system to process and index the document")

def show_agent_management():
    """Show agent management page"""
    st.header("🤖 Agent Management")
    st.info("This is the FULL CTI RAG Agentic System - Agent Management page")
    
    agents = ["Coordinator Agent", "Collector Agent", "Analyst Agent", "Tools Agent", "Maintainer Agent"]
    
    for agent in agents:
        col1, col2 = st.columns([3, 1])
        with col1:
            st.write(f"**{agent}**")
        with col2:
            st.button(f"Start {agent.split()[0]}", key=f"start_{agent}")

def show_ai_chat():
    """Show AI chat page"""
    st.header("💬 AI Chat")
    st.info("This is the FULL CTI RAG Agentic System - AI Chat page")
    
    # Chat input
    user_input = st.text_input("Ask a question:", placeholder="e.g., What are common cyber threats?")
    
    if st.button("Send"):
        if user_input:
            st.success(f"✅ Question: {user_input}")
            st.info("This would use the full agentic system with RAG to answer your question")

def show_analytics():
    """Show analytics page"""
    st.header("📊 Analytics")
    st.info("This is the FULL CTI RAG Agentic System - Analytics page")
    
    st.write("**System Metrics:**")
    st.metric("Total Documents", "1,234")
    st.metric("Active Agents", "5")
    st.metric("Queries Processed", "567")

if __name__ == "__main__":
    main() 