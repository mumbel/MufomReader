/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package mufom;

public class MufomSymbol {
	private String symbolName;
	private long symbolAddress;
	private long attributeDefinition;
	private long symbolIndex;
	
	public MufomSymbol(String name, long address, long attr, long index) {
		symbolName = name;
		symbolAddress = address;
		attributeDefinition = attr;
		symbolIndex = index;
	}
	
	public String getName() {
		return symbolName;
	}
	public long getAddress() {
		return symbolAddress;
	}
	public long getAttributeDefinition() {
		return attributeDefinition;
	}
	public long getSymbolIndex() {
		return symbolIndex;
	}
}
