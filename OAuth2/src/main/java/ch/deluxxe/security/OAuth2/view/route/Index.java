package ch.deluxxe.security.OAuth2.view.route;

import com.vaadin.flow.component.html.H3;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.Route;

@Route("")
public class Index extends VerticalLayout{

	/**
	 * 
	 */
	private static final long serialVersionUID = 7289640385600849375L;

	public Index() {
		add(new H3("Bitte rufen sie diese Seite durch eine Appliktaion auf."));
		this.setAlignItems(Alignment.CENTER);
	}
}
