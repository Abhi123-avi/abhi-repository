let dropArea; // Declare dropArea globally

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

function highlight() {
    dropArea.classList.add('highlight');
}

function unhighlight() {
    dropArea.classList.remove('highlight');
}

async function handleDrop(e) {
    const dt = e.dataTransfer;
    const files = dt.files;

    // Ensure that only one file is dropped
    if (files.length !== 1) {
        alert('Please drop only one file');
        return;
    }

    const file = files[0];
    const fileType = file.type;

    // Check if the dropped file is a PDF
    if (fileType !== 'application/pdf') {
        alert('Please drop a PDF file');
        return;
    }

    // Display the file name
    const fileNameDisplay = document.getElementById('fileNameDisplay');
    fileNameDisplay.textContent = `Uploaded File: ${file.name}`;

    // Proceed with file upload and analysis
    const fileInput = document.getElementById('fileInput');
    fileInput.files = files;
    checkFile();
}

document.addEventListener('DOMContentLoaded', () => {
    const checkBtn = document.getElementById('checkFileBtn');
    const fileInput = document.getElementById('fileInput');
    const dropArea = document.getElementById('dropArea');
    const dropText = document.querySelector('.click-to-upload');
    const fileNameDisplay = document.getElementById('fileNameDisplay'); // Get the file name display element

    function displayFileName(fileName) {
        fileNameDisplay.textContent = `Uploaded File: ${fileName}`; // Display the file name
    }

    function clearFileName() {
        fileNameDisplay.textContent = ''; // Clear the file name display
    }

    // Prevent default drag behaviors
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropArea.addEventListener(eventName, preventDefaults, false);
    });

    // Highlight drop area when file is dragged over it
    ['dragenter', 'dragover'].forEach(eventName => {
        dropArea.addEventListener(eventName, highlight, false);
    });

    // Unhighlight drop area when file is dragged out of it
    ['dragleave', 'drop'].forEach(eventName => {
        dropArea.addEventListener(eventName, unhighlight, false);
    });

    // Handle dropped files
    dropArea.addEventListener('drop', handleDrop, false);

    // Click event listener for 'click to upload' text
    dropText.addEventListener('click', () => {
        fileInput.click(); // Trigger file input when 'click to upload' text is clicked
    });

    // Change event listener for file input
    fileInput.addEventListener('change', () => {
        const files = fileInput.files;
        if (files.length === 1) {
            const fileType = files[0].type;
            if (fileType !== 'application/pdf') {
                alert('Please select a PDF file');
                fileInput.value = ''; // Clear the file input
                clearFileName(); // Clear the file name display
                return;
            }
            displayFileName(files[0].name); // Display the file name
            checkFile();
        } else {
            alert('Please select only one file');
            fileInput.value = ''; // Clear the file input
            clearFileName(); // Clear the file name display
        }
    });

    // Function to handle file drop
    async function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;

        // Ensure that only one file is dropped
        if (files.length !== 1) {
            alert('Please drop only one file');
            return;
        }

        const file = files[0];
        const fileType = file.type;

        // Check if the dropped file is a PDF
        if (fileType !== 'application/pdf') {
            alert('Please drop a PDF file');
            return;
        }

        // Proceed with file upload and analysis
        fileInput.files = files;
        displayFileName(file.name); // Display the file name
        checkFile();
    }
});



async function checkFile() {
    const apiKey = '47b4e237eb761d6421af3440c0f82a321049a3c1ffbd08b22dc9af713f7cbcfe';
    const fileInput = document.getElementById('fileInput');
    const modal = document.getElementById('myModal');
    const resultDiv = document.getElementById('result');
    resultDiv.innerHTML = '';

    const file = fileInput.files[0];
    if (!file) {
        alert('Please select a file');
        return;
    }

    const hash = await calculateFileHash(file);
    if (!hash) {
        alert('Unable to calculate hash');
        return;
    }

    try {
        const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
            headers: {
                'x-apikey': apiKey
            }
        });
        const data = await response.json();
        if (response.ok) {
            displayResult(data);
            modal.style.display = "block"; // Show modal after displaying result
        } else {
            alert('Error: ' + data.error.message);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred, please try again later.');
    }
}

function displayResult(data) {
    const resultDiv = document.getElementById('result');

    // Check if any malicious things were found
    const hasMalicious = data.data.attributes.total > 0;

    // Display relevant information from the API response
    const fileInfo = data.data.attributes;
    let message = '';

    if (hasMalicious) {
        // Display error message with red cross icon
        message = `<div style="color: red; font-size: 24px;">&#10060; Possible malicious things found!</div>`;
    } else {
        // Display success message with green checkmark icon
        message = `<div style="color: green; font-size: 24px;">&#10004; No malicious things found!</div>`;
    }

    const resultHTML = `
    <h2>File Information:</h2>
    ${message}
    <ul>
    
    <li><strong>Name:</strong> ${fileInfo.names.join(', ')}</li>
    <li><strong>Size:</strong> ${fileInfo.size} bytes</li>
    <li><strong>Type:</strong> ${fileInfo.type}</li>
    <li><strong>First Seen:</strong> ${fileInfo.first_seen}</li>
    <li><strong>Last Seen:</strong> ${fileInfo.last_seen}</li>
    <li><strong>Times Submitted:</strong> ${fileInfo.times_submitted}</li>
    <li><strong>Times Detected:</strong> ${fileInfo.times_detected}</li>
    <li><strong>Number of Engines Detected:</strong> ${fileInfo.last_analysis_results ? Object.keys(fileInfo.last_analysis_results).length : 0}</li>
    <li><strong>Reputation:</strong> ${fileInfo.reputation}</li>
    <li><strong>Trusted Votes:</strong> ${fileInfo.trusted_votes}</li>
    <li><strong>Malicious Votes:</strong> ${fileInfo.malicious_votes}</li>
    <li><strong>Category:</strong> ${fileInfo.category}</li>
    <li><strong>Last Modification Date:</strong> ${fileInfo.last_modification_date}</li>
    <li><strong>Total Votes:</strong> ${fileInfo.total_votes}</li>
    <li><strong>MD5:</strong> ${fileInfo.md5}</li>
    <li><strong>SHA-1:</strong> ${fileInfo.sha1}</li>
    <li><strong>SHA-256:</strong> ${fileInfo.sha256}</li>
    <li><strong>Magic:</strong> ${fileInfo.magic}</li>
    <li><strong>Entropy:</strong> ${fileInfo.entropy}</li>
    <li><strong>First Bytes (hex):</strong> ${fileInfo.first_bytes}</li>
    <li><strong>Times Analysed:</strong> ${fileInfo.times_analysed}</li>
    <li><strong>Downloadable:</strong> ${fileInfo.downloadable}</li>
    <li><strong>Upload Timestamp:</strong> ${fileInfo.upload_timestamp}</li>
    <li><strong>Scan Date:</strong> ${fileInfo.scan_date}</li>
    <li><strong>Positives:</strong> ${fileInfo.positives}</li>
    <li><strong>Total:</strong> ${fileInfo.total}</li>
    <li><strong>Tags:</strong> ${fileInfo.tags}</li>
    <li><strong>Similar Samples:</strong> ${fileInfo.similar_samples}</li>
    <li><strong>Meaningful Name:</strong> ${fileInfo.meaningful_name}</li>
    <li><strong>Period:</strong> ${fileInfo.period}</li>
    <li><strong>Size Lit Endian:</strong> ${fileInfo.size_little_endian}</li>
    <li><strong>Signature Exists:</strong> ${fileInfo.signature_exists}</li>
    <li><strong>Detected Engines:</strong> ${fileInfo.detected_engines}</li>
    <li><strong>Submitted From:</strong> ${fileInfo.submitted_from}</li>
    <li><strong>Verdict:</strong> ${fileInfo.verdict}</li>
    <li><strong>Meaningful Name Unicode:</strong> ${fileInfo.meaningful_name_unicode}</li>
    <li><strong>First Seen ITW:</strong> ${fileInfo.first_seen_itw}</li>
    <li><strong>File Type Extension:</strong> ${fileInfo.file_type_extension}</li>
    <li><strong>Analysis Start Time:</strong> ${fileInfo.analysis_start_time}</li>
    <li><strong>Analysis End Time:</strong> ${fileInfo.analysis_end_time}</li>
    <li><strong>Number of ITW Names:</strong> ${fileInfo.num_itw_names}</li>
    <li><strong>Times Executed:</strong> ${fileInfo.times_executed}</li>
    <li><strong>Original Signature:</strong> ${fileInfo.original_signature}</li>
    <li><strong>PE Compile Time:</strong> ${fileInfo.pe_compile_time}</li>
    <li><strong>URLs:</strong> ${fileInfo.urls}</li>
    <li><strong>File Name:</strong> ${fileInfo.file_name}</li>
    <li><strong>File Size:</strong> ${fileInfo.file_size}</li>
    <li><strong>Resource:</strong> ${fileInfo.resource}</li>
    <li><strong>Packer:</strong> ${fileInfo.packer}</li>
    <li><strong>Code Size:</strong> ${fileInfo.code_size}</li>
    <li><strong>Preferred Dumper:</strong> ${fileInfo.preferred_dumper}</li>

    <!-- Add more information as needed -->
    </ul>
    `;

    resultDiv.innerHTML = resultHTML;

    // Show modal after displaying result
    const modal = document.getElementById('myModal');
    modal.style.display = "block";

    // Close modal after 10 seconds
    setTimeout(() => {
        modal.style.display = "none";
    }, 15000);
}


function calculateFileHash(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = function (event) {
            const arrayBuffer = event.target.result;
            crypto.subtle.digest('SHA-256', arrayBuffer).then(hashBuffer => {
                const hashArray = Array.from(new Uint8Array(hashBuffer));

                const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
                resolve(hashHex);
            }).catch(error => reject(error));
        };
        reader.onerror = function (error) {
            reject(error);
        };
        reader.readAsArrayBuffer(file);
    });
}

// Get the modal
const modal = document.getElementById('myModal');

// Get the <span> element that closes the modal
const span = document.getElementsByClassName('close')[0];

// When the user clicks the 'x' button, close the modal
span.onclick = function () {
    modal.style.display = "none";
}

// When the user clicks anywhere outside of the modal, close it
window.onclick = function (event) {
    if (event.target == modal) {
        modal.style.display = "none";
    }
}






