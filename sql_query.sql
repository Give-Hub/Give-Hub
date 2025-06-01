create database finl_gh;
use finl_gh;

CREATE TABLE donations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    donor_name VARCHAR(255) NOT NULL,
    contact_number VARCHAR(20),
    email VARCHAR(255),
    medicine VARCHAR(255) NOT NULL,
    quantity INT NOT NULL,
    expiry_date DATE,
    address TEXT NOT NULL,
    message TEXT,
    image_filename VARCHAR(255),
    status VARCHAR(50) DEFAULT 'Pending', -- For admin approval
    medical_store_id INT, -- To assign to a medical store
    medical_store_status VARCHAR(50) DEFAULT 'Pending', -- For medical store action
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (medical_store_id) REFERENCES medical_stores(id)
);

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL, -- This will store hashed passwords
    role VARCHAR(50) DEFAULT 'User' -- e.g., 'User', 'Admin', 'Medical Store', 'NGO'
);

CREATE TABLE medical_stores (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    contact_number VARCHAR(20),
    address TEXT,
    password_hash VARCHAR(255), -- If medical stores also log in directly
    approved BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    medicine VARCHAR(255) NOT NULL,
    quantity INT NOT NULL,
    requester_name VARCHAR(255) NOT NULL,
    contact_number VARCHAR(20),
    address TEXT,
    doctor_letter LONGBLOB, -- To store the PDF/image file data
    status VARCHAR(50) DEFAULT 'Pending', -- e.g., 'Pending', 'Approved', 'Rejected', 'Partially Approved'
    requester_id INT, -- Link to the user who made the request
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (requester_id) REFERENCES users(id)
);

ALTER TABLE donations
ADD COLUMN quantity INT NOT NULL DEFAULT 0;


DESCRIBE users;
select*from requests;
select*from request_beneficiaries;
-- If you have a password_hash column in medical_stores, remove it:
ALTER TABLE medical_stores DROP COLUMN password_hash;

-- Ensure your medical_stores table looks like this:
DROP TABLE IF EXISTS medical_stores;
DESCRIBE donations;
---
## Corrected `medical_stores` Table Schema

DESCRIBE medicine_inventory_central;
DESCRIBE requests;

CREATE TABLE medical_stores (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL UNIQUE, -- This is the missing column, links to users.id
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    contact_number VARCHAR(20),
    address TEXT,
    -- password_hash VARCHAR(255), -- Remove this; medical stores should log in via 'users' table
    approved BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

INSERT INTO medical_stores (user_id, name, email, contact_number, address, approved)
VALUES (6, 'med2 Pharmacy', 'creativesolutions122024@gmail.com', '9876543210', '123 Medical Store Road, City, State, Zip', TRUE);

-- Delete requests made by users with IDs '1', '4', or '7'
DELETE FROM `finl_gh`.`requests` WHERE `requester_id` IN ('1', '4', '7');

-- Now, you can safely delete the users
DELETE FROM `finl_gh`.`users` WHERE (`id` = '1');
DELETE FROM `finl_gh`.`users` WHERE (`id` = '4');
DELETE FROM `finl_gh`.`users` WHERE (`id` = '7');

SHOW CREATE TABLE donations;
DESCRIBE requests;
select*from users;
ALTER TABLE donations DROP FOREIGN KEY donations_ibfk_1;

SELECT id, medicine, quantity, medical_store_status FROM donations;

CREATE TABLE ngos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    contact_person VARCHAR(255),
    contact_number VARCHAR(20),
    address TEXT,
    registration_number VARCHAR(255) UNIQUE,
    approved BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

ALTER TABLE users
ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

CREATE TABLE medicine_inventory_central (
    id INT AUTO_INCREMENT PRIMARY KEY,
    medicine_name VARCHAR(255) NOT NULL,
    description TEXT,
    manufacturer VARCHAR(255),
    stock_quantity INT NOT NULL DEFAULT 0,
    unit_price DECIMAL(10, 2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

SELECT u.email, u.name AS user_name, ms.name AS store_name, ms.approved
FROM users u
JOIN medical_stores ms ON u.id = ms.user_id
WHERE u.role = 'Medical Store';
ALTER TABLE medicine_inventory_central ADD COLUMN expiry_date DATE;
ALTER TABLE medicine_inventory_central ADD COLUMN status VARCHAR(50) DEFAULT 'Available';
DESCRIBE medicine_inventory_central;
select*from ngos;
select*from users;

DESCRIBE requests;


ALTER TABLE medicine_inventory_central
ADD COLUMN batch_no VARCHAR(100) NOT NULL,
ADD COLUMN received_from_donation_id INT NULL, -- Link back to the original donation (optional, but good for tracking)
ADD COLUMN received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- When it was added to central inventory
ADD COLUMN current_location VARCHAR(100) DEFAULT 'Central Hub'; -- 'Central Hub', 'Medical Store A', etc.

CREATE TABLE medical_store_receipts (
      id INT AUTO_INCREMENT PRIMARY KEY,
      donation_id INT NOT NULL, -- Foreign key to donations table
      medical_store_id INT NOT NULL, -- Foreign key to medical_stores table
      medicine_name VARCHAR(255) NOT NULL, -- The specific medicine received
      batch_no VARCHAR(100) NOT NULL,
      received_quantity INT NOT NULL, -- Actual quantity received
      unit_price DECIMAL(10,2) NULL, -- Price per unit (optional but requested)
      expiry_date DATE NOT NULL,
      received_by_user_id INT NOT NULL, -- Who (Medical Store operator) received it (FK to users)
      received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      status VARCHAR(50) DEFAULT 'Pending Transfer' -- e.g., 'Pending Transfer', 'Transferred to Central'
  );
  -- Add foreign key constraints:
  ALTER TABLE medical_store_receipts ADD CONSTRAINT fk_msr_donation FOREIGN KEY (donation_id) REFERENCES donations(id);
  ALTER TABLE medical_store_receipts ADD CONSTRAINT fk_msr_ms FOREIGN KEY (medical_store_id) REFERENCES medical_stores(id);
  ALTER TABLE medical_store_receipts ADD CONSTRAINT fk_msr_user FOREIGN KEY (received_by_user_id) REFERENCES users(id);
  
  
  -- Assuming 'requests' table exists, alter it:
  ALTER TABLE requests RENAME COLUMN quantity TO num_beneficiaries;
  ALTER TABLE requests MODIFY COLUMN num_beneficiaries INT NOT NULL; -- Ensure it's not nullable
  -- ALTER TABLE requests ADD COLUMN delivery_address TEXT NULL; -- Optional
  
  CREATE TABLE request_beneficiaries (
      id INT AUTO_INCREMENT PRIMARY KEY,
      request_id INT NOT NULL, -- Foreign key to requests table
      beneficiary_name VARCHAR(255) NOT NULL,
      age INT NOT NULL,
      sex VARCHAR(20) NOT NULL, -- e.g., 'Male', 'Female', 'Other'
      doctor_prescription_path VARCHAR(255) NULL, -- Path to uploaded PDF
      prescription_uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      status VARCHAR(50) DEFAULT 'Pending' -- e.g., 'Pending', 'Approved', 'Fulfilled'
  );
  -- Add foreign key constraint:
  ALTER TABLE request_beneficiaries ADD CONSTRAINT fk_rb_request FOREIGN KEY (request_id) REFERENCES requests(id);
  CREATE TABLE inventory_transactions (
      id INT AUTO_INCREMENT PRIMARY KEY,
      medicine_id INT NOT NULL, -- Foreign key to medicine_inventory_central (the specific batch)
      request_id INT NOT NULL, -- Foreign key to requests table
      issued_quantity INT NOT NULL,
      issued_by_user_id INT NOT NULL, -- Who (Central Hub operator) issued it (FK to users)
      issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      transaction_type VARCHAR(50) NOT NULL DEFAULT 'Issue' -- 'Issue', 'Adjustment', etc.
  );
  -- Add foreign key constraints:
  ALTER TABLE inventory_transactions ADD CONSTRAINT fk_it_medicine FOREIGN KEY (medicine_id) REFERENCES medicine_inventory_central(id);
  ALTER TABLE inventory_transactions ADD CONSTRAINT fk_it_request FOREIGN KEY (request_id) REFERENCES requests(id);
  ALTER TABLE inventory_transactions ADD CONSTRAINT fk_it_user FOREIGN KEY (issued_by_user_id) REFERENCES users(id);
  
  -- SQL to add Central Hub User
-- REPLACE 'YOUR_GENERATED_HASH_HERE' with the actual hash from the Python script above.

INSERT INTO users (name, email, password, role)
VALUES ('Central Hub Operator', 'centralhub@gmail.com', 'scrypt:32768:8:1$LPLIRCMfYRzgXRws$48cc5e081b0351cdb189e373535048be1e45f85412865e381ef232fc1b4df0195135f7dda192b02754da8c6185074a141ce6b9fc1e91fa5556055b0b1e50f51e', 'Central Hub');

ALTER TABLE medicine_inventory_central
ADD COLUMN quantity INT NOT NULL DEFAULT 0;


ALTER TABLE medicine_inventory_central
ADD COLUMN overall_status VARCHAR(50);

USE finl_gh;
DESCRIBE medicine_inventory_central;

INSERT INTO users (name, email, password, role) 
VALUES ('Test Name', 'test@example.com', 'test_password', 'NGO');

CREATE TABLE donation_medicines (
    id INT AUTO_INCREMENT PRIMARY KEY,
    donation_id INT,
    medicine_name VARCHAR(255),
    quantity INT,
    expiry_date DATE,
    image_filename VARCHAR(255),
    FOREIGN KEY (donation_id) REFERENCES donations(id)
);
CREATE TABLE request_medicines (
    id INT AUTO_INCREMENT PRIMARY KEY,
    request_id INT,
    medicine_name VARCHAR(255),
    quantity INT,
    FOREIGN KEY (request_id) REFERENCES requests(id)
);


CREATE TABLE medical_store_stock (
    id INT AUTO_INCREMENT PRIMARY KEY,
    medical_store_id INT NOT NULL,
    medicine_name VARCHAR(255) NOT NULL,
    quantity INT NOT NULL,
    expiry_date DATE,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (medical_store_id) REFERENCES medical_stores(id)
);



ALTER TABLE requests
ADD COLUMN medical_store_id INT,
ADD FOREIGN KEY (medical_store_id) REFERENCES medical_stores(id);

USE finl_gh;

-- 1. Remove the 'medicine' column
ALTER TABLE donations DROP COLUMN medicine;

-- 2. Remove the 'quantity' column (it was added twice in your schema, but let's drop it if it exists from the first definition)
--    If you see an error like "Error 1091 (42000): Can't DROP 'quantity'; check that column/key exists", it means it wasn't there initially or already dropped.
ALTER TABLE donations DROP COLUMN quantity;

-- 3. Remove the 'expiry_date' column
ALTER TABLE donations DROP COLUMN expiry_date;

-- Optional: If you had a 'status' column in `donations` that was meant for individual medicines,
-- consider if 'overall_status' in `donations` and 'status' in `donation_medicines` (if you add it) are better.
-- For now, `status` in `donations` seems to be for the overall donation, which is fine.

CREATE TABLE central_inventory (
    id INT AUTO_INCREMENT PRIMARY KEY,
    medicine_name VARCHAR(255) NOT NULL,
    quantity INT NOT NULL,
    batch_no VARCHAR(100),
    expiry_date DATE,
    unit_price DECIMAL(10, 2), -- Optional, useful for tracking value
    current_location VARCHAR(255), -- e.g., 'Central Hub Warehouse A'
    received_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
select*from users;
select*from medical_stores;
ALTER TABLE medical_store_stock ADD COLUMN batch_no VARCHAR(100);
ALTER TABLE medical_store_stock ADD COLUMN unit_price DECIMAL(10, 2);

-- Add batch_no to the donation_medicines table
ALTER TABLE donation_medicines
ADD COLUMN batch_no VARCHAR(100);

USE finl_gh; -- Make sure you are in the correct database
ALTER TABLE central_inventory
ADD COLUMN received_from_donation_id INT NULL,
ADD CONSTRAINT fk_ci_donation FOREIGN KEY (received_from_donation_id) REFERENCES donations(id);

ALTER TABLE donations
ADD COLUMN medicine_name VARCHAR(255),
ADD COLUMN quantity INT,
ADD COLUMN batch_no VARCHAR(255),
ADD COLUMN expiry_date DATE;

-- Example SQL to modify the column (use with caution, ensure data backup)
ALTER TABLE donation_medicines MODIFY COLUMN medicine_name VARCHAR(255) NOT NULL;




-- To allow NULL values for 'medicine'
ALTER TABLE request_medicines MODIFY COLUMN medicine VARCHAR(255) NULL;

-- To set a default value (e.g., an empty string or 'N/A')
ALTER TABLE request_medicines ALTER COLUMN medicine SET DEFAULT '';

DESCRIBE request_medicines;

ALTER TABLE request_medicines ALTER COLUMN medicine_name SET DEFAULT '';



CREATE TABLE request_medicines (
    id INT AUTO_INCREMENT PRIMARY KEY,
    request_id INT NOT NULL,           -- Foreign key linking to the 'requests' table
    medicine_name VARCHAR(255) NOT NULL, -- The name of the medicine (previously 'medicine')
    quantity INT NOT NULL,             -- The quantity of the medicine
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP, -- Timestamp of when this record was created

    -- Define foreign key constraint to link with the 'requests' table
    -- Assuming your 'requests' table has an 'id' column as its primary key
    FOREIGN KEY (request_id) REFERENCES requests(id) ON DELETE CASCADE
    -- ON DELETE CASCADE: If a request is deleted, all associated medicine requests are also deleted.
    -- Consider ON DELETE RESTRICT or ON DELETE SET NULL based on your application's logic.
);