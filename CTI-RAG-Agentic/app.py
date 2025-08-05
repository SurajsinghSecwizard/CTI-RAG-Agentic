#!/usr/bin/env python3
"""
Simple test app for Railway deployment
"""
import streamlit as st
import os

st.set_page_config(
    page_title="CTI RAG Test",
    page_icon="🕵️",
    layout="wide"
)

st.title("🕵️ CTI RAG Agentic System - Railway Test")
st.markdown("---")

# Show current directory and files
st.header("📁 Current Directory")
st.code(os.getcwd())

st.header("📋 Files in Directory")
files = os.listdir(".")
st.code("\n".join(files))

st.header("✅ Railway Deployment Test")
st.success("If you can see this, Railway deployment is working!")

st.header("🔧 Next Steps")
st.info("""
1. ✅ Railway deployment working
2. 🔄 Next: Deploy full agentic system
3. 🎯 Goal: Full RAG functionality
""") 