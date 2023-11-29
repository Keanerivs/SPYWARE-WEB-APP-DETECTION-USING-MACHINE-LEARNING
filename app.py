# app.py
import streamlit as st
import joblib
import os
import pandas as pd
import pefile
from login_page import login

# Load the trained model
model = joblib.load('model.pkl')

def extract_features(file_path):
    try:
        pe = pefile.PE(file_path)

        # Replace this with the relevant features from your dataset
        features = {
            'e_magic': pe.DOS_HEADER.e_magic,
            'e_cblp': pe.DOS_HEADER.e_cblp,
            'e_cp': pe.DOS_HEADER.e_cp,
            'e_crlc': pe.DOS_HEADER.e_crlc,
            'e_cparhdr': pe.DOS_HEADER.e_cparhdr,
            'e_minalloc': pe.DOS_HEADER.e_minalloc,
            'e_maxalloc': pe.DOS_HEADER.e_maxalloc,
            'e_ss': pe.DOS_HEADER.e_ss,
            'e_sp': pe.DOS_HEADER.e_sp,
            'e_csum': pe.DOS_HEADER.e_csum,
            'e_ip': pe.DOS_HEADER.e_ip,
            'e_cs': pe.DOS_HEADER.e_cs,
            'e_lfarlc': pe.DOS_HEADER.e_lfarlc,
            'e_ovno': pe.DOS_HEADER.e_ovno,
            'e_oemid': pe.DOS_HEADER.e_oemid,
            'e_oeminfo': pe.DOS_HEADER.e_oeminfo,
            'e_lfanew': pe.DOS_HEADER.e_lfanew,
            'Machine': pe.FILE_HEADER.Machine,
            'NumberOfSections': pe.FILE_HEADER.NumberOfSections,
            'TimeDateStamp': pe.FILE_HEADER.TimeDateStamp,
            'PointerToSymbolTable': pe.FILE_HEADER.PointerToSymbolTable,
            'NumberOfSymbols': pe.FILE_HEADER.NumberOfSymbols,
            'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
            'Characteristics': pe.FILE_HEADER.Characteristics,
            'Magic': pe.OPTIONAL_HEADER.Magic,
            'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
            'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
            'SizeOfCode': pe.OPTIONAL_HEADER.SizeOfCode,
            'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
            'SizeOfUninitializedData': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'BaseOfCode': pe.OPTIONAL_HEADER.BaseOfCode,
            'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
            'SectionAlignment': pe.OPTIONAL_HEADER.SectionAlignment,
            'FileAlignment': pe.OPTIONAL_HEADER.FileAlignment,
            'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
            'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
            'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
            'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
            'Reserved1': pe.OPTIONAL_HEADER.Reserved1,
            'SizeOfImage': pe.OPTIONAL_HEADER.SizeOfImage,
            'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
            'CheckSum': pe.OPTIONAL_HEADER.CheckSum,
            'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
            'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
            'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
            'SizeOfHeapReserve': pe.OPTIONAL_HEADER.SizeOfHeapReserve,
            'SizeOfHeapCommit': pe.OPTIONAL_HEADER.SizeOfHeapCommit,
            'LoaderFlags': pe.OPTIONAL_HEADER.LoaderFlags,
            'NumberOfRvaAndSizes': pe.OPTIONAL_HEADER.NumberOfRvaAndSizes,
        }

        return list(features.values())

    except Exception as e:
        st.error(f"Error extracting features: {e}")
        return None

    

def predict_spyware(features):
    try:
        prediction = model.predict([features])[0]
        return bool(prediction), prediction
    except Exception as e:
        st.error(f"Error making prediction: {e}")
        return None, None

def main():
    st.title("Spyware Detection App")

    # Check if the user is authenticated
    is_authenticated = st.session_state.get('is_authenticated', False)

    if not is_authenticated:
        # Display login page
        username, password = st.text_input("Username:"), st.text_input("Password:", type="password")
        if st.button("Login"):
            # Your authentication logic here, for now let's consider any input as successful login
            st.session_state.is_authenticated = True
            st.session_state.username = username

    else:
        # Display Spyware Detection App
        st.write(f"Logged in as: {st.session_state.username}")

        # Your Spyware Detection App code here
        uploaded_file = st.file_uploader("Choose an executable file (.exe):", type="exe")

        if uploaded_file is not None:
            # Your existing code for processing the file
            file_path = os.path.join("uploads", uploaded_file.name)
            with open(file_path, "wb") as f:
                f.write(uploaded_file.getbuffer())

            extracted_features = extract_features(file_path)

            if extracted_features is not None:
                is_spyware, prediction = predict_spyware(extracted_features)

                st.header("Prediction Result:")
                st.write(f"Is Spyware: {is_spyware}")
                st.write(f"Prediction: {prediction}")

            else:
                st.error("Error extracting features.")
                 # Logout button
        if st.button("Logout"):
           
            st.session_state.is_authenticated = False
            st.experimental_rerun()

if __name__ == "__main__":
    main()