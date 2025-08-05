#!/usr/bin/env python3
"""
CTI RAG Agentic System - Real Agentic Implementation
Uses the actual multi-agent system like the local application
FORCE REDEPLOY - Railway deployment fix
"""

import streamlit as st
import asyncio
import os
import sys
import json
from datetime import datetime
from typing import List, Dict, Any

# Add the current directory to Python path for imports
sys.path.append(os.getcwd())

# Import the real agentic system
try:
    import config
    from agentic_system import AgenticCTISystem, get_agentic_system
    from agents import CoordinatorAgent, CollectorAgent, AnalystAgent, ToolsAgent, MaintainerAgent
except ImportError as e:
    st.error(f"Failed to import agentic system: {e}")
    st.stop()

# Page config
st.set_page_config(
    page_title="CTI RAG Agentic System",
    page_icon="🕵️",
    layout="wide"
)

# Initialize session state
if 'agentic_system' not in st.session_state:
    st.session_state.agentic_system = None
if 'is_initialized' not in st.session_state:
    st.session_state.is_initialized = False
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []
if 'workflow_results' not in st.session_state:
    st.session_state.workflow_results = []

async def initialize_agentic_system():
    """Initialize the agentic system"""
    try:
        # Create config
        cfg = config.Config()
        
        # Validate config
        if not config.Config.validate():
            st.error("❌ Configuration validation failed. Check environment variables.")
            return None
        
        # Create agentic system
        agentic_system = AgenticCTISystem(cfg)
        await agentic_system.initialize()
        
        st.session_state.is_initialized = True
        st.success("✅ Agentic system initialized successfully!")
        return agentic_system
        
    except Exception as e:
        st.error(f"❌ Failed to initialize agentic system: {e}")
        return None

def main():
    st.title("🕵️ CTI RAG Agentic System")
    st.markdown("---")
    
    # Sidebar for navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.selectbox(
        "Choose a page",
        ["System Status", "Threat Analysis", "Data Ingestion", "Agent Management", "AI Chat", "Analytics"]
    )
    
    # Initialize agentic system if not done
    if not st.session_state.is_initialized:
        st.header("🚀 Initializing Agentic System")
        st.info("Setting up the multi-agent CTI system...")
        
        if st.button("Initialize System", type="primary"):
            with st.spinner("Initializing agentic system..."):
                # Run async initialization
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    agentic_system = loop.run_until_complete(initialize_agentic_system())
                    if agentic_system:
                        st.session_state.agentic_system = agentic_system
                        st.rerun()
                finally:
                    loop.close()
        return
    
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
    st.header("⚙️ System Status")
    
    if not st.session_state.agentic_system:
        st.error("Agentic system not initialized")
        return
    
    # System information
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🔧 Environment")
        st.write(f"**Python Version:** {sys.version.split()[0]}")
        st.write(f"**Platform:** {sys.platform}")
        st.write(f"**Working Directory:** {os.getcwd()}")
        st.write(f"**Streamlit Version:** {st.__version__}")
    
    with col2:
        st.subheader("🌐 Application")
        st.success("**Status:** ✅ Running")
        st.write("**Framework:** Streamlit + Agentic System")
        st.write("**Deployment:** Azure App Service")
        st.write(f"**Start Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Agent status
    st.subheader("🤖 Agent Status")
    
    if st.button("Check Agent Status", type="primary"):
        with st.spinner("Checking agent status..."):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                status = loop.run_until_complete(st.session_state.agentic_system.get_agent_status())
                
                # Display agent status
                for agent_name, agent_info in status.get("agents", {}).items():
                    if agent_info.get("status") == "active":
                        st.success(f"✅ {agent_name}: Active")
                    else:
                        st.error(f"❌ {agent_name}: {agent_info.get('status', 'Unknown')}")
                
                # Display system health
                health = status.get("system_health", {})
                st.subheader("🏥 System Health")
                st.write(f"**Overall Status:** {health.get('status', 'Unknown')}")
                st.write(f"**Active Workflows:** {health.get('active_workflows', 0)}")
                st.write(f"**Resource Usage:** {health.get('resource_usage', 'Unknown')}")
                
            except Exception as e:
                st.error(f"Failed to get agent status: {e}")
            finally:
                loop.close()
    
    # Configuration status
    st.subheader("🔑 Configuration Status")
    cfg = config.Config()
    
    config_status = {
        "OpenAI API": bool(cfg.OPENAI_API_KEY),
        "Azure Search": bool(cfg.AZURE_SEARCH_ENDPOINT and cfg.AZURE_SEARCH_KEY),
        "Azure Storage": bool(cfg.AZURE_STORAGE_CONNECTION_STRING),
        "VirusTotal": bool(cfg.VIRUSTOTAL_API_KEY),
        "Abuse.ch": bool(cfg.ABUSE_CH_API_KEY)
    }
    
    for service, configured in config_status.items():
        if configured:
            st.success(f"✅ {service}: Configured")
        else:
            st.warning(f"⚠️ {service}: Not configured")

def show_threat_analysis():
    st.header("🎯 Threat Analysis")
    
    if not st.session_state.agentic_system:
        st.error("Agentic system not initialized")
        return
    
    # Threat actor selection
    st.subheader("Select Threat Actor")
    
    # Sample threat actors from config
    sample_actors = config.Config.SAMPLE_ACTORS
    threat_actor = st.selectbox("Choose threat actor:", sample_actors)
    
    # Analysis types
    st.subheader("Analysis Types")
    analysis_types = st.multiselect(
        "Select analysis types:",
        ["threat_profile", "tactics_techniques", "ioc_analysis", "attribution", "timeline"],
        default=["threat_profile", "tactics_techniques"]
    )
    
    # Run analysis
    if st.button("Run Threat Analysis", type="primary"):
        if not threat_actor:
            st.warning("Please select a threat actor")
            return
        
        with st.spinner(f"Running threat analysis for {threat_actor}..."):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(
                    st.session_state.agentic_system.run_threat_analysis_workflow(
                        threat_actor=threat_actor,
                        analysis_types=analysis_types
                    )
                )
                
                # Display results
                st.success("✅ Threat analysis completed!")
                
                # Store results
                st.session_state.workflow_results.append({
                    "type": "threat_analysis",
                    "threat_actor": threat_actor,
                    "result": result,
                    "timestamp": datetime.now()
                })
                
                # Display analysis results
                st.subheader("📊 Analysis Results")
                
                if "workflow_result" in result:
                    workflow_result = result["workflow_result"]
                    
                    # Display each step result
                    for step_name, step_result in workflow_result.items():
                        with st.expander(f"Step: {step_name}"):
                            if isinstance(step_result, dict):
                                for key, value in step_result.items():
                                    st.write(f"**{key}:** {value}")
                            else:
                                st.write(step_result)
                
                # Display summary
                if "summary" in result:
                    st.subheader("📋 Summary")
                    st.write(result["summary"])
                
            except Exception as e:
                st.error(f"❌ Threat analysis failed: {e}")
            finally:
                loop.close()
    
    # Display previous results
    if st.session_state.workflow_results:
        st.subheader("📚 Previous Analysis Results")
        for i, result in enumerate(reversed(st.session_state.workflow_results)):
            if result["type"] == "threat_analysis":
                with st.expander(f"{result['threat_actor']} - {result['timestamp'].strftime('%Y-%m-%d %H:%M')}"):
                    st.write(f"**Threat Actor:** {result['threat_actor']}")
                    st.write(f"**Analysis Time:** {result['timestamp']}")
                    if "summary" in result["result"]:
                        st.write(f"**Summary:** {result['result']['summary']}")

def show_data_ingestion():
    st.header("📥 Data Ingestion")
    
    if not st.session_state.agentic_system:
        st.error("Agentic system not initialized")
        return
    
    st.subheader("Ingest Threat Intelligence Data")
    
    # Source selection
    sources = st.multiselect(
        "Select data sources:",
        ["all", "threat_reports", "malware_samples", "ioc_feeds", "vulnerability_data"],
        default=["all"]
    )
    
    if st.button("Run Ingestion Workflow", type="primary"):
        with st.spinner("Running ingestion workflow..."):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(
                    st.session_state.agentic_system.run_ingestion_workflow(sources=sources)
                )
                
                st.success("✅ Ingestion workflow completed!")
                
                # Display results
                st.subheader("📊 Ingestion Results")
                if "ingestion_stats" in result:
                    stats = result["ingestion_stats"]
                    st.write(f"**Documents Processed:** {stats.get('documents_processed', 0)}")
                    st.write(f"**Documents Added:** {stats.get('documents_added', 0)}")
                    st.write(f"**Processing Time:** {stats.get('processing_time', 'Unknown')}")
                
            except Exception as e:
                st.error(f"❌ Ingestion failed: {e}")
            finally:
                loop.close()

def show_agent_management():
    st.header("🤖 Agent Management")
    
    if not st.session_state.agentic_system:
        st.error("Agentic system not initialized")
        return
    
    st.subheader("Agent Operations")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("Check System Health", type="primary"):
            with st.spinner("Checking system health..."):
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    health = loop.run_until_complete(
                        st.session_state.agentic_system.monitor_system_health()
                    )
                    
                    st.success("✅ System health check completed!")
                    
                    # Display health metrics
                    st.subheader("🏥 Health Metrics")
                    for metric, value in health.items():
                        st.write(f"**{metric}:** {value}")
                        
                except Exception as e:
                    st.error(f"❌ Health check failed: {e}")
                finally:
                    loop.close()
    
    with col2:
        if st.button("Optimize Resources", type="primary"):
            with st.spinner("Optimizing resources..."):
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    result = loop.run_until_complete(
                        st.session_state.agentic_system.optimize_resources(apply_optimizations=True)
                    )
                    
                    st.success("✅ Resource optimization completed!")
                    
                    # Display optimization results
                    st.subheader("⚡ Optimization Results")
                    if "recommendations" in result:
                        for rec in result["recommendations"]:
                            st.write(f"• {rec}")
                            
                except Exception as e:
                    st.error(f"❌ Optimization failed: {e}")
                finally:
                    loop.close()

def show_ai_chat():
    st.header("💬 AI Chat with Agentic System")
    
    if not st.session_state.agentic_system:
        st.error("Agentic system not initialized")
        return
    
    st.write("Chat with the AI using the agentic system's knowledge and capabilities.")
    
    # Chat input
    user_input = st.text_input("Your question:", placeholder="Tell me about APT29's latest activities...")
    
    col1, col2 = st.columns([3, 1])
    with col1:
        if st.button("💬 Send", type="primary"):
            if user_input:
                process_agentic_chat_message(user_input)
    with col2:
        if st.button("🗑️ Clear Chat"):
            st.session_state.chat_history = []
            st.rerun()
    
    # Chat history
    st.subheader("💬 Chat History")
    for message in st.session_state.chat_history:
        if message["role"] == "user":
            st.write(f"**You:** {message['content']}")
        else:
            st.write(f"**AI:** {message['content']}")

def process_agentic_chat_message(message):
    """Process chat message using the agentic system"""
    # Add user message to history
    st.session_state.chat_history.append({"role": "user", "content": message})
    
    # Use the analyst agent to process the message
    with st.spinner("Processing with agentic system..."):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            # Create a simple analysis task
            task = {
                "type": "analysis",
                "query": message,
                "analysis_type": "chat_response"
            }
            
            # This would need to be implemented in the analyst agent
            # For now, we'll use a simple response
            ai_response = f"Agentic system received: {message}. This would be processed by the Analyst Agent with access to the full threat intelligence knowledge base."
            
            st.session_state.chat_history.append({"role": "assistant", "content": ai_response})
            
        except Exception as e:
            error_response = f"Error processing message: {e}"
            st.session_state.chat_history.append({"role": "assistant", "content": error_response})
        finally:
            loop.close()

def show_analytics():
    st.header("📈 Analytics Dashboard")
    
    if not st.session_state.agentic_system:
        st.error("Agentic system not initialized")
        return
    
    st.subheader("System Analytics")
    
    # Get workflow status
    if st.button("Get Workflow Analytics", type="primary"):
        with st.spinner("Getting analytics..."):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                workflow_status = loop.run_until_complete(
                    st.session_state.agentic_system.get_workflow_status()
                )
                
                st.success("✅ Analytics retrieved!")
                
                # Display workflow metrics
                st.subheader("📊 Workflow Metrics")
                if "metrics" in workflow_status:
                    metrics = workflow_status["metrics"]
                    st.write(f"**Total Workflows:** {metrics.get('total_workflows', 0)}")
                    st.write(f"**Completed Workflows:** {metrics.get('completed_workflows', 0)}")
                    st.write(f"**Failed Workflows:** {metrics.get('failed_workflows', 0)}")
                    st.write(f"**Average Execution Time:** {metrics.get('avg_execution_time', 'Unknown')}")
                
            except Exception as e:
                st.error(f"❌ Failed to get analytics: {e}")
            finally:
                loop.close()
    
    # Display previous results summary
    if st.session_state.workflow_results:
        st.subheader("📚 Recent Activity")
        
        # Count by type
        threat_analyses = [r for r in st.session_state.workflow_results if r["type"] == "threat_analysis"]
        st.write(f"**Threat Analyses Performed:** {len(threat_analyses)}")
        
        # Show recent threat actors
        if threat_analyses:
            recent_actors = [r["threat_actor"] for r in threat_analyses[-5:]]
            st.write(f"**Recent Threat Actors:** {', '.join(recent_actors)}")

if __name__ == "__main__":
    main() 