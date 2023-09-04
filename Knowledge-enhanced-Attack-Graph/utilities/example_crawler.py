from bs4 import BeautifulSoup
import networkx as nx
import requests


# Crawl procedure examples from Mitre Att&ck website
if __name__ == "__main__""":
    G = nx.Graph()
    soup = BeautifulSoup()
    url = 'https://attack.mitre.org/'
    resp = requests.get(url)
    soup = BeautifulSoup(resp.text)
    tech = []

    links = soup.find_all('tr', class_="technique-row")
    for link in links:
        techName = link.find("a").text
        techUrl = link.find("a")["href"]

        if techName not in tech:
            tmps = link.find_all("div", class_="subtechnique")
            # Technique
            if len(tmps) == 0:
                tech.append(techName)
                print(techUrl)
                G.add_node(techUrl, name=techName, types="technique")

                # examples
                url = 'https://attack.mitre.org' + techUrl
                resp = requests.get(url)
                soup = BeautifulSoup(resp.text)
                examples = soup.find_all('h2', {'id': 'examples'})
                if len(examples) != 0:
                    procedure_example_table = soup.find('table', {'class': 'table table-bordered table-alternate mt-2'})
                    for produce_examples in procedure_example_table.find_all('tr')[1:]:
                        produce_name = produce_examples.find_all('a')[0].text
                        produce_url = produce_examples.find_all('a')[0]['href']
                        print(produce_url)
                        example_description = produce_examples.find_all('p')[0].text
                        print(example_description)
                        G.add_node(example_description, types='examples')
                        G.add_edge(techUrl, example_description, types='examples')

            # Super Technique
            else:
                tech.append(techName)
                print(techUrl)
                G.add_node(techUrl, name=techName, types='super_technique')
                for tmp in tmps:
                    sub_techName = tmp.find("a").text
                    sub_techUrl = tmp.find("a")["href"]
                    print(sub_techUrl)
                    G.add_node(sub_techUrl, name=sub_techName, types='sub_technique')
                    G.add_edge(sub_techUrl, techUrl, types='belong to')

                    # examples
                    url = 'https://attack.mitre.org' + sub_techUrl
                    resp = requests.get(url)
                    soup = BeautifulSoup(resp.text)
                    examples = soup.find_all('h2', {'id': 'examples'})
                    if len(examples) != 0:
                        procedure_example_table = soup.find('table', {'class': 'table table-bordered table-alternate mt-2'})
                        for produce_examples in procedure_example_table.find_all('tr')[1:]:
                            produce_name = produce_examples.find_all('a')[0].text
                            produce_url = produce_examples.find_all('a')[0]['href']
                            print(produce_url)
                            example_description = produce_examples.find_all('p')[0].text
                            print(example_description)
                            G.add_node(example_description, types='examples')
                            G.add_edge(sub_techUrl, example_description, types='examples')

        else:
            print("Repeated: ", techName, techUrl)


    nx.write_gml(G, "Tactic_Technique_Reference_Example_latest.gml")


