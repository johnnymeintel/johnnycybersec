from faker import Faker
import random

fake = Faker()

# Generate INSERT statements for employees
departments = ['Engineering', 'Sales', 'Marketing', 'Finance', 'HR', 'IT', 'Operations']

with open('employees_insert.sql', 'w', encoding='utf-8') as f:
    f.write("USE cjcs_corporate;\n\n")
    
    for i in range(100):
        first_name = fake.first_name().replace("'", "''")
        last_name = fake.last_name().replace("'", "''")
        email = fake.email()
        department = random.choice(departments)
        job_title = fake.job().replace("'", "''")
        hire_date = fake.date_between(start_date='-10y', end_date='today').strftime('%Y-%m-%d')
        salary = random.randint(45000, 150000)
        ssn = f"{random.randint(0, 9999):04d}"
        phone = fake.phone_number().replace("'", "")[:15]
        address = (fake.street_address() + ' ' + fake.city() + ' ' + fake.state_abbr() + ' ' + fake.zipcode()).replace("'", "''")[:200]
        
        sql = f"INSERT INTO employees (first_name, last_name, email, department, job_title, hire_date, salary, ssn_last_four, phone, address) VALUES ('{first_name}', '{last_name}', '{email}', '{department}', '{job_title}', '{hire_date}', {salary}, '{ssn}', '{phone}', '{address}');\n"
        f.write(sql)

print("[+] Generated employees_insert.sql")

# Generate INSERT statements for customers
with open('customers_insert.sql', 'w', encoding='utf-8') as f:
    f.write("USE cjcs_corporate;\n\n")
    
    for i in range(200):
        company = fake.company().replace("'", "''")
        contact = fake.name().replace("'", "''")
        email = fake.email()
        phone = fake.phone_number().replace("'", "")[:15]
        cc = f"{random.randint(0, 9999):04d}"
        value = round(random.uniform(1000, 500000), 2)
        created = fake.date_between(start_date='-5y', end_date='today').strftime('%Y-%m-%d')
        
        sql = f"INSERT INTO customers (company_name, contact_name, email, phone, credit_card_last_four, account_value, created_date) VALUES ('{company}', '{contact}', '{email}', '{phone}', '{cc}', {value}, '{created}');\n"
        f.write(sql)

print("[+] Generated customers_insert.sql")

# Generate INSERT statements for invoices
payment_statuses = ['Paid', 'Pending', 'Overdue', 'Cancelled']
payment_methods = ['Credit Card', 'Wire Transfer', 'Check', 'ACH']

with open('invoices_insert.sql', 'w', encoding='utf-8') as f:
    f.write("USE cjcs_corporate;\n\n")
    
    for i in range(300):
        customer_id = random.randint(1, 200)
        invoice_date = fake.date_between(start_date='-2y', end_date='today').strftime('%Y-%m-%d')
        amount = round(random.uniform(100, 50000), 2)
        status = random.choice(payment_statuses)
        method = random.choice(payment_methods)
        
        sql = f"INSERT INTO invoices (customer_id, invoice_date, amount, payment_status, payment_method) VALUES ({customer_id}, '{invoice_date}', {amount}, '{status}', '{method}');\n"
        f.write(sql)

print("[+] Generated invoices_insert.sql")
print("\n[✓] All SQL files generated")
print("    - employees_insert.sql")
print("    - customers_insert.sql")
print("    - invoices_insert.sql")