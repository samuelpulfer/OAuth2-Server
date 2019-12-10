package ch.deluxxe.security.OAuth2.view;

import java.util.HashSet;
import java.util.Set;

import com.vaadin.flow.component.Key;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.html.Label;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import ch.deluxxe.security.OAuth2.view.ifaces.LoginView;


public class LoginViewImpl extends VerticalLayout implements LoginView {
	
	/**
	 * Generated Serial Version ID
	 */
	private static final long serialVersionUID = -6487930553565163659L;
	
	

	private Set<LoginListener> listeners = new HashSet<>();
	
	private TextField username = new TextField();
	private PasswordField password = new PasswordField();
	private Label message = new Label();
	private Label application = new Label();
	private Button login = new Button("Login");
	
	public LoginViewImpl() {
		username.setLabel("Benutzername");
		password.setLabel("Passwort");
		password.addKeyUpListener(Key.ENTER, event -> {
			for(LoginListener listener:listeners) {
				listener.login(username.getValue(), password.getValue());
			}
		});
		message.setVisible(false);
		application.setText("Unbekannte Applikation");
		login.addClickListener(event -> {
			for(LoginListener listener:listeners) {
				listener.login(username.getValue(), password.getValue());
			}
			
		});
		add(new H1("OAuth2 Login"),username,password,login,message,application);
		this.setAlignItems(Alignment.CENTER);
	}

	@Override
	public void setMessage(String message) {
		this.message.setText(message);
		this.message.setVisible(true);
	}
	
	@Override
	public void setApplication(String application) {
		this.application.setText(application);
	}	

	@Override
	public void addLoginListener(LoginListener listener) {
		listeners.add(listener);		
	}

	@Override
	public void removeLoginListener(LoginListener listener) {
		listeners.remove(listener);
	}

	
}
