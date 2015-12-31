/********************************************************************************/
/* 																				*/
/* Copyright [2016]	Robson de Melo Silva,										*/
/* 					Vitoria Akemi Kanegae,										*/
/* 					Jose Ricardo de Oliveira Damico								*/
/* 																				*/
/* Licensed under the Apache License, Version 2.0 (the "License");				*/
/* you may not use this file except in compliance with the License.				*/
/* You may obtain a copy of the License at										*/
/* 																				*/
/*     http://www.apache.org/licenses/LICENSE-2.0								*/
/* 																				*/
/* Unless required by applicable law or agreed to in writing, software			*/
/* distributed under the License is distributed on an "AS IS" BASIS,			*/
/* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.		*/
/* See the License for the specific language governing permissions and			*/
/* limitations under the License.												*/
/*																				*/
/********************************************************************************/

package br.com.eigmercados.signature.ui;

import java.awt.Dimension;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.security.SignatureException;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

import org.apache.pdfbox.exceptions.COSVisitorException;
import org.jdamico.scryptool.commons.TopLevelException;
import org.jdamico.scryptool.crypto.EmbedSignature;
import org.jdamico.scryptool.crypto.PKCS11_Helper;

public class SignatureUI extends JFrame implements ActionListener {

	private static final long serialVersionUID = 1L;
	private JLabel labelName = new JLabel("Selecione o Arquivo:");
	private JTextField fileName = new JTextField();
	private JButton buttonSelect = new JButton("Procurar");
	private JFileChooser fileChooser = new JFileChooser();
	private JFileChooser selectDll = new JFileChooser();
	private JButton signButton = new JButton("Assinar");
	private JButton selectDllButton = new JButton("Alterar DLL");
	private final String dllSource = "C:\\Windows\\System32\\aetpkss1.dll";
	private String dllAlternativePath;

	public SignatureUI() {

		this.setLayout(null);
		this.setTitle("Assinatura de documentos");
		scaleComponents();
		addComponentes();
		buttonSelect.addActionListener(this);
		signButton.addActionListener(this);
		selectDllButton.addActionListener(this);
		fileName.addActionListener(this);
		this.setVisible(true);
	}

	private void scaleComponents() {
		Dimension dim = Toolkit.getDefaultToolkit().getScreenSize();
		int xLocation = (dim.width /2 ) - 300;
		int yLocation = (dim.height /2) - 100 ;
		this.setBounds(xLocation, yLocation, 600, 200);

		this.setResizable(false);
		this.setDefaultCloseOperation(DISPOSE_ON_CLOSE);
		labelName.setBounds(10, 10, 130, 50);
		fileName.setBounds(150, 25, 300, 25);
		buttonSelect.setBounds(470, 25, 100, 25);
		signButton.setBounds(250,70, 100, 30);
		selectDllButton.setBounds(480, 135, 100, 25);
	}

	private void addComponentes() {
		this.add(labelName);
		this.add(fileName);
		this.add(buttonSelect);
		this.add(signButton);
		this.add(selectDllButton);
	}

	@Override
	public void actionPerformed(ActionEvent e) {

		if (e.getSource() == buttonSelect) {
			int returnVal = fileChooser.showOpenDialog(this);
			if (returnVal == JFileChooser.APPROVE_OPTION) {
				selectFile();
			}

		} else if(e.getSource() == signButton){
			if (fileName.getText().isEmpty()){
				JOptionPane.showMessageDialog(null, "Favor inserir o documento!", "Falha", JOptionPane.ERROR_MESSAGE);
			}else{
				signDocumento();
			}
		} else if(e.getSource() == selectDllButton){
			int returnVal = fileChooser.showOpenDialog(this);
			if (returnVal == JFileChooser.APPROVE_OPTION) {
				selectDll();
			}
		}
	}
	private void selectDll(){
		File file = selectDll.getSelectedFile();
		setDllAlternativePath(file.getAbsolutePath());
	}

	private void selectFile(){
		File file = fileChooser.getSelectedFile();
		fileName.setText(file.getAbsolutePath());
	}

	private void signDocumento(){
		File arquivo = new File(fileName.getText());
		JPasswordField pf = new JPasswordField();
		int opt = JOptionPane.showConfirmDialog(null,pf,"Digite a senha do Token.",JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
		String libPath;

		if(opt == JOptionPane.OK_OPTION){
			String senha = new String (pf.getPassword());
			if(getDllAlternativePath() != null ){
				libPath = getDllAlternativePath();
			}else{
				libPath = dllSource;
			}
			
			if(fileName.getText().endsWith(".pdf")){
				EmbedSignature emb = new EmbedSignature();
				try{
					emb.signPDF(arquivo, libPath, senha.toString());
					JOptionPane.showMessageDialog(null, "Documento assinado com sucesso e salvo em : "+arquivo.getParent()+"\\signed\\"+arquivo.getName(), "Sucesso", JOptionPane.INFORMATION_MESSAGE);
				} catch (SignatureException e) {
					e.printStackTrace();
					JOptionPane.showMessageDialog(null, "Falha ao Executar a Assinatura!", "Falha", JOptionPane.ERROR_MESSAGE);
				} catch (IOException e) {
					e.printStackTrace();
					JOptionPane.showMessageDialog(null, "Falha ao Executar a Assinatura!", "Falha", JOptionPane.ERROR_MESSAGE);
				} catch (COSVisitorException e) {
					e.printStackTrace();
					JOptionPane.showMessageDialog(null, "Falha ao Executar a Assinatura!", "Falha", JOptionPane.ERROR_MESSAGE);
				} catch (org.apache.pdfbox.exceptions.SignatureException e) {
					e.printStackTrace();
					JOptionPane.showMessageDialog(null, "Falha ao Executar a Assinatura!", "Falha", JOptionPane.ERROR_MESSAGE);
				}finally{
					this.dispose();
				}
			}else{
				JOptionPane.showMessageDialog(null, "Para documentos diferentes de PDF as asinaturas são geradas em arquivos separados", "Atenção", JOptionPane.WARNING_MESSAGE);
				PKCS11_Helper pki = new PKCS11_Helper();
				try {
					pki.signSelectedFile(arquivo, libPath, senha.toString());
					JOptionPane.showMessageDialog(null, "Documento assinado com sucesso e salvo em : "+arquivo.getParent()+"\\signed\\"+arquivo.getName()+".signature", "Sucesso", JOptionPane.INFORMATION_MESSAGE);
				} catch (TopLevelException e) {
					JOptionPane.showMessageDialog(null, "Falha ao Executar a Assinatura!", "Falha", JOptionPane.ERROR_MESSAGE);
					e.printStackTrace();
				}
			}
		}
	}

	private String getDllAlternativePath() {
		return dllAlternativePath;
	}

	private void setDllAlternativePath(String localAlternativoDll) {
		this.dllAlternativePath = localAlternativoDll;
	}	
}
