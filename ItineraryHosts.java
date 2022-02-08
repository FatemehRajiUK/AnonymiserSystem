//=============================================================================
// The itinerary host is a host visited by the anonymous agent. 
// The agent is anonymous not only regarding the network observer but also the itinerary hosts.

// Please refer to the following journal article published in IET Information Security Journal for more information:
// F. Raji, B. T. Ladani, Anonymity and Security for Autonomous Mobile Agents, IET Information Security, Special Issue on Multi-Agent and Distributed Information Security, Vol.  4, No. 4, pp. 397 - 410, 2010.
//=============================================================================

/*****************************************************************
JADE - Java Agent DEvelopment Framework is a framework to develop 
multi-agent systems in compliance with the FIPA specifications.
Copyright (C) 2000 CSELT S.p.A. 

GNU Lesser General Public License

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation, 
version 2.1 of the License. 

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the
Free Software Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA  02111-1307, USA.
*****************************************************************/

import java.util.Random;
import jade.core.Runtime;
import jade.core.*;
import jade.core.behaviours.CyclicBehaviour;
import jade.core.behaviours.OneShotBehaviour;
import jade.wrapper.ContainerController;
import jade.wrapper.AgentController;
  public class ItineraryHosts extends Agent 
  { 
      protected void setup() 
      { 
          int maxMixer = 5;          
          for(int i=1;i<maxMixer;++i)
          {
          Runtime r = Runtime.instance();  
          ProfileImpl p=new ProfileImpl();
          p.setParameter(Profile.CONTAINER_NAME, "Itinerary Host-"+i);
          //Profile p = new ProfileImpl();
          ContainerController cc = r.createAgentContainer(p);          
          }//end for
   //       ContainerController cc2 = r.createAgentContainer(p);
          
  		addBehaviour(new OneShotBehaviour(this) 
				{
					
					 public void action() 
					 {

						boolean done=false;
						int num=0;
						int min = 1;
				        int max = 4;
				        Agent a=this.myAgent;
				       	jade.core.Location location = a.here();
			         	String name = location.getName();
			        	System.out.println(name);
			        	System.out.println(a.getAgentState());
			        			
			        	Random rand = new Random();
				        num = rand.nextInt(max-min+1)+min;
						//System.out.println("num is : "+num);
			
						String containerName = "Itinerary Host-"+num;
					    ContainerID destination = new ContainerID();
						destination.setName(containerName);
						doMove(destination);	
						
						location = a.here();
			         	name = location.getName();
			        	System.out.println(name);
			        	System.out.println("The anonymous agent's state is: "+a.getAgentState());
			        	
					 block();
				 }
			});
  }
}
