#!/usr/bin/env python3
"""
Simple test app to verify Railway deployment
"""

import streamlit as st

st.set_page_config(
    page_title="SIMPLE TEST - CTI RAG Agentic System",
    page_icon="🕵️",
    layout="wide"
)

st.title("🕵️ SIMPLE TEST - CTI RAG Agentic System")
st.success("✅ This is the SIMPLE TEST version - Railway deployment working!")

st.write("**If you can see this, Railway is serving the correct app!**")

st.header("Test Components:")
st.write("✅ Streamlit is working")
st.write("✅ Railway deployment is working")
st.write("✅ This is the correct app")

st.header("Next Steps:")
st.write("1. This confirms Railway can serve the app")
st.write("2. Now we can deploy the full agentic system")
st.write("3. All environment variables are set correctly")

st.info("🎉 SUCCESS! Railway deployment is working correctly!") 