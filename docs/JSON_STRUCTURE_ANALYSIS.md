# API Documentation JSON Structure Analysis
**Author:** Lorenzo Albanese (alblor)  
**Created:** August 26, 2025  
**Purpose:** Comprehensive JSON keyword consistency analysis for frontend filtering

## 🎯 **Perfect JSON Consistency Achieved**

### **Root Level Keys (100% Consistent Across All 9 Endpoints)**
```json
{
  "author": "Lorenzo Albanese (alblor)",
  "base_url": "http://localhost:8000", 
  "last_updated": "ISO-8601-timestamp",
  "manpage": { /* structured content */ },
  "section": "endpoint-type-identifier",
  "title": "Human readable title",
  "version": "2.0.0-secure"
}
```

### **Standard Filtering Keywords**

#### **By Endpoint Type**
```bash
# Documentation sections
curl /v1/docs | jq '.section'  # Returns: "index"
curl /v1/docs/overview | jq '.section'  # Returns: "overview" 
curl /v1/docs/modes | jq '.section'  # Returns: "modes"
curl /v1/docs/endpoints | jq '.section'  # Returns: "endpoints"
curl /v1/docs/auth | jq '.section'  # Returns: "auth"
curl /v1/docs/examples | jq '.section'  # Returns: "examples"
curl /v1/docs/errors | jq '.section'  # Returns: "errors"
curl /v1/docs/tools | jq '.section'  # Returns: "tools"
curl /v1/docs/endpoints/{id} | jq '.section'  # Returns: "endpoint"
```

#### **By Content Type**
```bash
# Filter by manpage content type
curl /v1/docs | jq 'select(.manpage.sections)'  # Has sections array
curl /v1/docs/examples | jq 'select(.manpage.workflows)'  # Has workflows
curl /v1/docs/endpoints | jq 'select(.manpage.endpoints)'  # Has endpoints array
curl /v1/docs/endpoints/submit_job | jq 'select(.manpage.parameters)'  # Has parameters
```

## 📊 **ManPage Structure Patterns**

### **Universal ManPage Keys (Present in ALL endpoints)**
- `"name"`: Endpoint/section name
- `"synopsis"`: Brief description  
- `"description"`: Detailed explanation

### **Content-Specific ManPage Keys**

#### **Documentation Index (`/v1/docs`)**
```json
{
  "sections": [/* array of documentation sections */],
  "quick_links": {/* key-value pairs of important endpoints */}
}
```

#### **System Overview (`/v1/docs/overview`)**
```json
{
  "architecture": {/* system architecture details */},
  "key_features": [/* array of feature descriptions */],
  "quick_start": [/* array of setup steps */]
}
```

#### **Encryption Modes (`/v1/docs/modes`)**
```json
{
  "automated_mode": {/* automated encryption details */},
  "manual_mode": {/* manual encryption details */},
  "security_comparison": {/* comparison table */}
}
```

#### **Endpoints List (`/v1/docs/endpoints`)**
```json
{
  "endpoints": [/* array of API endpoint objects */],
  "usage": {/* usage guidelines */}
}
```

#### **Individual Endpoints (`/v1/docs/endpoints/{id}`)**
```json
{
  "method": "GET|POST|PUT|DELETE",
  "path": "/api/endpoint/path",
  "authentication": "required|optional|none",
  "content_type": "application/json|multipart/form-data",
  "parameters": [/* parameter objects */],
  "responses": [/* response objects */],
  "examples": [/* example objects */],
  "workflow_notes": [/* workflow guidance */]
}
```

#### **Workflow Examples (`/v1/docs/examples`)**
```json
{
  "workflows": {
    "automated_basic": {/* basic automated workflow */},
    "automated_advanced": {/* advanced automated workflow */},
    "manual_complete": {/* complete manual workflow */},
    "batch_processing": {/* batch processing workflow */}
  },
  "troubleshooting": {/* troubleshooting guidance */}
}
```

#### **Error Reference (`/v1/docs/errors`)**
```json
{
  "error_format": {/* standard error response format */},
  "http_status_codes": {/* HTTP status code meanings */},
  "error_types": {/* error categorization */},
  "common_scenarios": [/* common error scenarios */]
}
```

#### **Client Tools (`/v1/docs/tools`)**
```json
{
  "tools_overview": {/* tools description */},
  "installation": {/* installation instructions */},
  "encrypt_media_py": {/* encrypt_media.py documentation */},
  "decrypt_media_py": {/* decrypt_media.py documentation */},
  "manual_mode_workflow": {/* complete workflow guide */}
}
```

## 🔍 **Advanced Filtering Examples**

### **Frontend-Ready Queries**
```javascript
// Get all documentation sections for navigation
fetch('/v1/docs').then(r => r.json()).then(d => d.manpage.sections)

// Get all workflow examples for tutorial system
fetch('/v1/docs/examples').then(r => r.json()).then(d => d.manpage.workflows)

// Get all API endpoints for interactive explorer
fetch('/v1/docs/endpoints').then(r => r.json()).then(d => d.manpage.endpoints)

// Filter endpoints by method
fetch('/v1/docs/endpoints/submit_job').then(r => r.json())
  .then(d => d.manpage.method === 'POST' ? d : null)

// Get error codes for error handling
fetch('/v1/docs/errors').then(r => r.json())
  .then(d => d.manpage.http_status_codes)
```

### **JQ Command Line Filtering**
```bash
# Get all section titles for menu
curl /v1/docs | jq '.manpage.sections[].title'

# Get all POST endpoints
curl /v1/docs/endpoints | jq '.manpage.endpoints[] | select(.method=="POST")'

# Get workflow names
curl /v1/docs/examples | jq '.manpage.workflows | keys[]'

# Get all error codes
curl /v1/docs/errors | jq '.manpage.http_status_codes | keys[]'

# Filter by authentication requirement
curl /v1/docs/endpoints/submit_job | jq 'select(.manpage.authentication=="required")'
```

## 🏗️ **Frontend Component Mapping**

### **Navigation Components**
- **Main Menu**: Use `.manpage.sections` from `/v1/docs`
- **Quick Links**: Use `.manpage.quick_links` from `/v1/docs`
- **Breadcrumbs**: Use `.section` and `.title` from any endpoint

### **Content Components**
- **API Explorer**: Use `.manpage.endpoints` from `/v1/docs/endpoints`
- **Tutorial System**: Use `.manpage.workflows` from `/v1/docs/examples`
- **Error Handler**: Use `.manpage.error_types` from `/v1/docs/errors`
- **Code Examples**: Use `.manpage.examples` from individual endpoints

### **Interactive Components**
- **Form Builder**: Use `.manpage.parameters` from individual endpoints
- **Response Viewer**: Use `.manpage.responses` from individual endpoints
- **Curl Generator**: Use `.manpage.examples` from any endpoint

## ✅ **Quality Assurance**

### **Consistency Verified**
- ✅ **100% consistent root-level keys** across all 9 endpoints
- ✅ **Standardized section identifiers** for reliable filtering
- ✅ **Predictable manpage structure** for each content type
- ✅ **Comprehensive filtering keywords** for all use cases

### **Frontend Integration Ready**
- ✅ **Structured navigation data** for menu systems
- ✅ **Dynamic content filtering** for search and categorization
- ✅ **Interactive examples** for API exploration
- ✅ **Real-time updates** through consistent timestamp fields

This analysis confirms that the API documentation system provides **perfect JSON consistency** for easy frontend filtering and dynamic content management.