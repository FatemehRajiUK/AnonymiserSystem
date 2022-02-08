//=============================================================================
// An auxiliary host named as Mixers is developed to be part of the anonymiser system. 
// The owner sends its agent to the anonymiser system that provides a transient virtual owner for the agent in each step of its itinerary. 
// This means that any host in the network cannot learn the true identity of the agent owner and the path which the agent has traversed through so far. 

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
import jade.core.AID;
import jade.core.Agent;
import jade.core.Profile;
import jade.core.ContainerID;
import jade.core.ProfileImpl;
import jade.core.Runtime;
import jade.core.behaviours.*;
import jade.domain.DFService;
import jade.domain.FIPAException;
import jade.domain.FIPAAgentManagement.DFAgentDescription;
import jade.domain.FIPAAgentManagement.ServiceDescription;
import jade.lang.acl.*;
import jade.wrapper.AgentController;
import jade.wrapper.ContainerController;
import java.io.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;    
import jade.domain.JADEAgentManagement.CreateAgent;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.print.DocFlavor.BYTE_ARRAY;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import java.lang.Object;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;

public class MixerAgent extends Agent 
{
	 static int Sym_Key_Size=128; 
	 static String Sym_alg="AES"; 

	 static int Asym_Key_Size=1024; 
	 static int BlockSize=128;///512 64;
     static String Asym_alg="RSA"; 

	 static int Agent_length=800;
	 static double P=0;
	 static String pubkeyfile="PublicKey.key";
	 static String Agentfile="code.java";
	 
	 PrivateKey prvk;
     PublicKey pubk ;
     
	 state AgentState=new state();
	 String CurMixer;


	 private  byte[] SymEncrypt(byte[] inpBytes, 
	     SecretKey key, String xform) throws Exception { 
	     Cipher cipher = Cipher.getInstance(xform); 
	     cipher.init(Cipher.ENCRYPT_MODE, key); 	      
	     return cipher.doFinal(inpBytes); 
	   } 


	   private  byte[] SymDecrypt(byte[] inputBytes,SecretKey key, String xform) throws Exception { 
	     Cipher cipher = Cipher.getInstance(xform); 
	     cipher.init(Cipher.DECRYPT_MODE, key); 
	     return cipher.doFinal(inputBytes); 
	   } 


	   private  byte[] AsymEncrypt(byte[] inputBytes, PublicKey key, String xform) throws Exception { 
	    Cipher cipher = Cipher.getInstance(xform); 
	    cipher.init(Cipher.ENCRYPT_MODE, key); 
	    return cipher.doFinal(inputBytes); 
	  } 


	   private  byte[] AsymDecrypt(byte[] inputBytes,PrivateKey key, String xform) throws Exception{ 
	    Cipher cipher = Cipher.getInstance(xform);
	    cipher.init(Cipher.DECRYPT_MODE, key); 
	    byte[] tmp=cipher.doFinal(inputBytes);
	    return tmp;
	  } 


	   private  String padding(String in){ 
	  while (in.length()<Agent_length){ 
	  in=in.concat("$"); 
	  } 
	  return in; 
	   }

	   private  String unpadding(String in){
		   int j=in.length();
		   while (in.substring(j-1,j).equals("$")){ 
			  --j; 
			  }
		   return in.substring(0,j); 
			   }


	   public  int unsignedByteToInt(byte b) {
	 		return (int) b & 0xFF;
	 	}


	   private  byte[] FullPubKeys()throws Exception
	   {
	 	  FileInputStream fis = new FileInputStream(pubkeyfile);
	       ByteArrayOutputStream baos = new ByteArrayOutputStream();
	       int b;
	       try
	       {
	                   while ((b = fis.read()) != -1)
	                   {
	                       baos.write(b);
	                   }
	                   fis.close();
	                   baos.flush();
	                   baos.close();
	       } catch (IOException e) {
	    	   System.out.println("MIXER  ");
	    	   e.printStackTrace();
	       }
	       return baos.toByteArray();
	 }


	   private int FindPubKey(byte[] bc,byte[] b)throws Exception
	   {
	 	  byte first = b[0];
	 	  int start =0;
	 	  int end = bc.length;
	 	  byte[] buff=new byte[end];
	 	  int srcEnd = b.length;
	 	  buff=bc;
	 	  for (int i = start; i <= (end - srcEnd); i++) 
	 	  {   if (buff[i] != first) continue;
	 		  int myPos = i+1;
	 		  for (int srcPos = 1; srcPos < srcEnd; ) 
	 		  {	
	 			  if (buff[myPos++] != (b[srcPos++]))
	 				  break;
	 			  if (srcPos == srcEnd) return i - start; // found it
	 		  }
	 	}
	 	return -1;
	   }


		private void ExtractState(String str)throws Exception
		{	
		int i0=str.indexOf("***",0);
		AgentState.Address=str.substring(0,i0);

		int i1=str.indexOf("***",i0+3);
		try{
		X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(Base64.decode(str.substring(i0+3,i1)));
	 	KeyFactory kf = KeyFactory.getInstance(Asym_alg);
	 	PublicKey pubk= kf.generatePublic(pkSpec);
		AgentState.X=pubk;
		}
		catch (Exception e) 
        { 
	        System.err.println ("Exception in ExtractState: "+e.getMessage()); 
	        System.exit(-1); 
        }

		int i2=str.indexOf("***",i1+3);
		AgentState.Ret_Addr=str.substring(i1+3,i2).getBytes();
		
		int i3=str.indexOf("***",i2+3);
		AgentState.Result=str.substring(i2+3,i3).getBytes();
		
		int i4=str.indexOf("***",i3+3);
		AgentState.Mixer_Action=str.substring(i3+3,i4);
		
		AgentState.Code=str.substring(i4+3,str.length());		
}
		

	   private int Coin_Filp(double p)throws Exception
	   {		   
		double flip=Math.random();
		//System.out.println("The result of coin flipping is "+flip);
    	if(flip<p)
    		return 1;
    	return 0;
	   }


	   private int Pickup()throws Exception
	   {
			boolean done=false;
			int num=0;
			int min = 1;
	        int max = 4;
	        while(!done)
			{
		        Random rand = new Random();
		        num = rand.nextInt(max-min+1)+min;
				if(("mixer agent"+num).compareToIgnoreCase(CurMixer)!=0)
					done=true;
				else
					{
						;
					//  System.out.println("No intermediate mixer is selected");
					}
			}
	        return num;
	   }


	   private void CreateAgentClass()
	   {
		   try
		   {
			   FileOutputStream fout = new FileOutputStream(Agentfile,false); 
			   new PrintStream(fout).println(AgentState.getCode());
			   fout.close(); 
		   }
		   catch (Exception e) 
		   {   System.out.println("Exception in CreateAgentClass:");
			   e.printStackTrace();
		   } 
	   }


	public void setup() 
    {
    	addBehaviour(new OneShotBehaviour(this)
    		{
    		 public void action() 
			 {
    			try{
		    	KeyPairGenerator kpg = KeyPairGenerator.getInstance(Asym_alg);
		        kpg.initialize(Asym_Key_Size);
		        KeyPair kp = kpg.generateKeyPair();
		        pubk = kp.getPublic();
		        prvk = kp.getPrivate();
		        
		        String IDmixer="Mixer-"+myAgent.getLocalName().substring(11);
		    	FileOutputStream fout = new FileOutputStream(pubkeyfile,true); 
		    	new PrintStream(fout).println(IDmixer+"\t"+Base64.encode(pubk.getEncoded()));
		    	fout.close(); 
    			}
    			catch (Exception e) 
    	      	{
    			 System.out.println("Exception in OneShotBehaviour: ");
    	    	 e.printStackTrace();
    	      	}
			 }
    		});
    	
    	addBehaviour(new CyclicBehaviour(this) 
			{
				 public void action() 
				 {					 
				 try{					 
					setQueueSize(5);
					ACLMessage msg = receive();
					if (msg!=null) 
					{   
						System.out.println("----------------------------");
						System.out.println("The current time is "+System.currentTimeMillis());
						byte[] rmsg;//=new byte[size];
						rmsg=(byte[])msg.getContentObject();
						int size=rmsg.length;
						int i,j,keysize=BlockSize;
						int l=rmsg.length-keysize;
						
						byte[] rencBytes=new byte[l];
						byte[] renckey=new byte[keysize];
						for(i=0;i<l;++i)
							rencBytes[i]=rmsg[i];
						for(i=rmsg.length-1,j=BlockSize-1;i>=l;--i,--j)
							renckey[j]=rmsg[i];						
						byte[] deckey = AsymDecrypt(renckey, prvk, Asym_alg);
					    
					    SecretKey skey= new SecretKeySpec(deckey, "AES"); 
					    byte[] decBytes = SymDecrypt(rencBytes, skey, Sym_alg); 

					    String str1 = new String(decBytes); 
					    String str2=unpadding(str1);
						ExtractState(str2);

						if(AgentState.getMixer_Action().compareTo("Save-Retaddr")==0)
						{
							Cipher cipher = Cipher.getInstance("RSA//ECB/NoPadding");
			                cipher.init(Cipher.ENCRYPT_MODE, pubk);
			                byte[] cipherRet_Adrr="".getBytes();
			                byte[] rec_retaddr=AgentState.getRet_Addr();
			                
			                ContainerController cc=myAgent.getContainerController();
					        String containerName = cc.getContainerName();				        
					        long dd=System.currentTimeMillis();
			                cipherRet_Adrr = cipher.doFinal(rec_retaddr);
			                System.out.println("The current time is " + System.currentTimeMillis()-dd);	
			                cipherRet_Adrr=(new String(cipherRet_Adrr).concat(new String(containerName))).getBytes();
			                AgentState.setRet_Addr(cipherRet_Adrr);
						}				
						
						if(AgentState.getMixer_Action().compareTo("Exe-Mission")==0 || AgentState.getMixer_Action().compareTo("Save-Retaddr")==0)									
						{						
							int t=Coin_Filp(P);
							if(t==1)
								{
								CurMixer=myAgent.getLocalName();
								int num=Pickup();							
						        String IDnextmixer="Mixer-"+num;
						        KeyGenerator kg = KeyGenerator.getInstance(Sym_alg); 
							    kg.init(Sym_Key_Size); 
							    SecretKey key = kg.generateKey(); 
						    	String data=AgentState.getAddress().concat("***"+Base64.encode(AgentState.getX().getEncoded()));
							    data=data.concat("*** The agent's return address is: "+AgentState.getRet_Addr());
							    data=data.concat("*** The agent's result field is: "+AgentState.getResult());
							    data=data.concat("*** The agent's mixer action is: "+AgentState.getMixer_Action());
							    data=data.concat("*** The agent's code is: "+AgentState.getCode());
					            data=padding(data);     
							    byte[] dataBytes = data.getBytes(); 
							    byte[] encBytes = SymEncrypt(dataBytes, key, Sym_alg); 							      
							    byte[] keybyte =key.getEncoded(); 
							    byte[] ff=FullPubKeys();
							    int k=FindPubKey(ff,IDnextmixer.getBytes());
							    int a=IDnextmixer.length()+1;
							    int m=0;
							    for(i=k+a,j=0;i<ff.length;++i,++j)
							     	{
							 		if(ff[i]!=10)//"\n"
							 			++m;
							 		else 
							 			break;
							     	}
							    	byte[] ss=new byte[m-1];
							    	for(i=k+a,j=0;j<m-1;++i,++j)
							    		ss[j]=ff[i];
										
							    String pk = new String(ss);
							    X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(Base64.decode(pk));
							 	KeyFactory kf = KeyFactory.getInstance(Asym_alg);
							 	PublicKey nextpubk= kf.generatePublic(pkSpec);
							 	long d=System.currentTimeMillis();
							    byte[] enckey = AsymEncrypt(keybyte, nextpubk, Asym_alg);
							    System.out.println(System.currentTimeMillis()-d);	
							    int size2=encBytes.length+enckey.length;
							    byte[] message=new byte[size2];
							    
							    for(i=0;i<encBytes.length;++i)
							    	message[i]=encBytes[i];
							    for(i=encBytes.length,j=0;i<size2;++i,++j)
							    	message[i]=enckey[j];
							    ACLMessage msg2 = new ACLMessage(ACLMessage.INFORM);						
							    msg2.setContentObject(message);
								AID ai=new AID( "mixer agent"+num, AID.ISLOCALNAME); 
							    msg2.addReceiver( ai);       
								send(msg2);
								System.out.println("From "+myAgent.getLocalName() +", Sending a message to Mixer"+num);
								}//end if t==1
							 else
							    {
								 System.out.println("selecting itinerary host");
								 Object [] args = new Object[6];
							     args[0] = AgentState.getAddress();
							     args[1] = Base64.encode(AgentState.getX().getEncoded());
							     args[2]=AgentState.getRet_Addr();
							     args[3]=AgentState.getResult();
							     args[4]=AgentState.getMixer_Action();
							     args[5]=AgentState.getCode();
							     CreateAgentClass();
								 ContainerController cc=myAgent.getContainerController();
								 Random r = new Random();
								 String name = "ANO"+Long.toString(Math.abs(r.nextLong()), 10);
									AgentController ac=null ;
									try 
									{
										ac = cc.createNewAgent(name,"AnonymousAgent",args);
										ac.start();
									}
									 catch(Exception e) 
									{
										System.out.println("Exception in selecting itinerary host: "+e.getMessage());
									}		
								String containerName = AgentState.getAddress();
							    ContainerID destination = new ContainerID();
								destination.setName(containerName);
								System.out.println("E "+System.currentTimeMillis());
								ac.move(destination);								
								     }
						}//end if	
						else//AgentState.getMixer_Action().compareTo("Back-Home")==0								
						{
							Cipher decipher = Cipher.getInstance("RSA/ECB/NoPadding");
			                decipher.init(Cipher.DECRYPT_MODE, prvk);		                               
			                byte[] rec_retaddr=AgentState.getRet_Addr();
			                
			                int index=new String(rec_retaddr).indexOf("Mixer");
			                
			                rec_retaddr=(new String(rec_retaddr).substring(index-BlockSize,index)).getBytes();			                
			                byte[] rec_retaddr2=decipher.doFinal(rec_retaddr);
					        AgentState.setRet_Addr(rec_retaddr2);
					        if((index=new String(rec_retaddr).indexOf("Mixer"))>=0)
			                {
				                String RetMixer2=new String(rec_retaddr).substring(index,rec_retaddr.length);
				                int num=Integer.parseInt(RetMixer2.substring(RetMixer2.length()-1,RetMixer2.length()));
				                ACLMessage msg2 = new ACLMessage(ACLMessage.INFORM);						
							    msg2.setContentObject("hello");
								AID ai=new AID( "mixer agent"+num, AID.ISLOCALNAME); 
							    msg2.addReceiver( ai);       
								send(msg2);
								System.out.println("from "+myAgent.getLocalName() +" send message to mixer"+num);
				             }
			                else
			                {
			                	index=new String(rec_retaddr2).indexOf("null,");
			                	String owner=new String(rec_retaddr2).substring(index+5,rec_retaddr2.length);
				               
			                	ACLMessage msg2 = new ACLMessage(ACLMessage.INFORM);						
							    msg2.setContentObject("hello");
								AID ai=new AID(owner, AID.ISLOCALNAME); 
							    msg2.addReceiver( ai);       
								send(msg2);
			                	System.out.println("Returning back the anonymous agent to its owner");
							}	
						}//end else				  
					}//end if msg
				 }//end try
			        catch (Exception e) 
			        { 
				        System.err.println ("General exception in the Mixer:  "+e.toString()); 
				        System.exit(-1); 
			        }					
				 block();			 
			 }
				});
	}//end set up
}
