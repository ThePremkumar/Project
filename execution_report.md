# ICTDS Execution Report

The Intelligent Cyber Threat Detection System (ICTDS) has been successfully initialized and is currently running. Below is a summary of the execution steps and the visual output.

## Execution Summary

1.  **Environment Setup**: Created a Python virtual environment and installed all dependencies from `requirements.txt`.
2.  **Model Loading**: The system automatically detected and loaded a pre-trained `RandomForest` and `GradientBoosting` ensemble model (trained on the CIC-IDS dataset).
3.  **Application Startup**: Launched the Flask backend on `http://127.0.0.1:5001`.
4.  **Verification**: Logged in as `admin` and executed a demo analysis to verify system integrity.

## Visual Output

````carousel
![Initial Dashboard](file:///C:/Users/prem/.gemini/antigravity/brain/c22cae48-c0e6-4e1c-97b4-78b0d5f4df83/artifacts/dashboard_screenshot_1778569457170.png)
<!-- slide -->
![Analysis Page](file:///C:/Users/prem/.gemini/antigravity/brain/c22cae48-c0e6-4e1c-97b4-78b0d5f4df83/artifacts/analyse_page_screenshot_1778569481290.png)
<!-- slide -->
![Post-Demo Dashboard](file:///C:/Users/prem/.gemini/antigravity/brain/c22cae48-c0e6-4e1c-97b4-78b0d5f4df83/artifacts/dashboard_after_demo_1778569604178.png)
````

## System Metrics (Post-Demo)

| Metric | Value |
| :--- | :--- |
| **Total Traffic Analysed** | 20 Packets |
| **Threats Detected** | 0 |
| **Safe Traffic** | 20 |
| **Detection Accuracy** | ~97% (CIC-IDS Model) |

## Browser Interaction Recording

You can view the full login and demo execution flow below:

![Login and Demo Flow](file:///C:/Users/prem/.gemini/antigravity/brain/c22cae48-c0e6-4e1c-97b4-78b0d5f4df83/artifacts/login_flow_1778569418478.webp)

> [!TIP]
> You can access the live dashboard at [http://127.0.0.1:5001](http://127.0.0.1:5001) using the credentials `admin` / `admin123`.
