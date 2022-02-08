//=============================================================================
// A public anonymiser system is simulated that is composed of a lot of auxiliary hosts referred as Mixers. 
// The owner sends its agent to Ano-Sys in an encrypted message in order to be resistant against traffic analysis attacks.

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

import jade.core.Runtime;
import jade.core.*;
import jade.wrapper.ContainerController;
import jade.wrapper.AgentController;
  public class AnoSys extends Agent 
  { 
      protected void setup() 
      { 
          int maxMixer = 5;
          for(int i=1;i<maxMixer;++i)
          {
          Runtime r = Runtime.instance();  
          ProfileImpl p=new ProfileImpl();
          p.setParameter(Profile.CONTAINER_NAME, "Mixer-"+i);
          //Profile p = new ProfileImpl();
          ContainerController cc = r.createAgentContainer(p);          
        
          if (cc != null) 
          {
	          try 
	          	{
	        	 // System.out.println(cc.getContainerName());
	        	  AgentController ac = cc.createNewAgent("mixer agent"+i,"MixerAgent",null);
	        	  
	        	  ac.start();
	          	}
	          catch (Exception e) 
	          	{
	        	  e.printStackTrace();
	          	}
          }
          }//end for
   //       ContainerController cc2 = r.createAgentContainer(p);
  }
}
