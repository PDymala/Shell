module app.diplabs.shell {
    requires javafx.controls;
    requires javafx.fxml;
    requires org.junit.jupiter.api;
    requires org.testng;


    opens app.diplabs.shell to javafx.fxml;
    exports app.diplabs.shell;
}