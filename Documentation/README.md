# OSINT-Driven CTI Framework for Coordinated Social Engineering Campaign Detection

## How to Run in Apache NetBeans
1. Open **MySQL Workbench** and execute `Implementation/database_setup.sql`.
2. In **Apache NetBeans**, create a new **Java with Ant -> Java Application** project inside `Implementation/`.
3. Copy the `com.cti.*` packages into `src/`.
4. Right-click **Libraries** in NetBeans -> **Add JAR/Folder** -> select `mysql-connector-j-8.x.x.jar`.
5. Update `PASSWORD` in `DatabaseManager.java` to match your MySQL password.
6. Run `CTIDashboardFrame.java` and click **2. Run OSINT & Graph Clustering**.
